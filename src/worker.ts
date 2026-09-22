import { Hono } from "hono";
import { JwtPlugin } from "./plugins/jwk";
import { cfAccessMiddleware } from "./plugins/cfAccess";
import { ServerProvider } from "./types/provider";
import * as jose from 'jose';
import {
	RESTPostOAuth2AccessTokenResult,
	APIUser,
	APIGuild,
	APIGuildMember,
} from 'discord-api-types/v10';

const jwtPlugin = new JwtPlugin();

export type Bindings = {
	KV: KVNamespace;
	CF_ACCESS_AUD?: string;
	CF_ACCESS_TEAM_DOMAIN?: string;
	ENVIRONMENT?: string;
	// Fallback static single-tenant environment variables
	DISCORD_CLIENT_ID?: string;
	DISCORD_CLIENT_SECRET?: string;
	DISCORD_CLIENT_TOKEN?: string;
	DISCORD_REDIRECT_URI?: string;
	SERVER_LIST?: string;
};

const app = new Hono<{
	Bindings: Bindings;
}>();

app.get("/", (c) => c.text("Discord OIDC Provider Worker is Running."));

/**
 * Helper to fetch provider config by serverId from KV or fallback to ENV.
 */
async function getProviderConfig(env: Bindings, serverId?: string): Promise<ServerProvider | null> {
	if (serverId && env.KV) {
		const raw = await env.KV.get(`provider:${serverId}`);
		if (raw) {
			try {
				return JSON.parse(raw) as ServerProvider;
			} catch (e) {
				console.error(`Failed to parse provider JSON for serverId: ${serverId}`, e);
			}
		}
	}

	// Fallback to static env configuration if available
	if (env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) {
		return {
			serverId: serverId || env.SERVER_LIST || 'default',
			serverName: 'Default Server',
			clientId: env.DISCORD_CLIENT_ID,
			clientSecret: env.DISCORD_CLIENT_SECRET,
			botToken: env.DISCORD_CLIENT_TOKEN || '',
			redirectUri: env.DISCORD_REDIRECT_URI || '',
		};
	}

	return null;
}

// OAuth Authorize Route
app.get('/authorize/:scopemode', async (c) => {
	const { scopemode } = c.req.param();
	const { redirect_uri, state, server_id } = c.req.query();

	const scopeMode = {
		email: 'identify email',
		guilds: 'identify email guilds',
		roles: 'identify email guilds guilds.members.read',
	};

	if (scopemode === undefined || !Object.keys(scopeMode).includes(scopemode)) {
		return c.text('Invalid scope mode', 400);
	}

	// Resolve provider config either by requested server_id or client_id
	const targetServerId = server_id || (c.req.query('server') as string);
	const provider = await getProviderConfig(c.env, targetServerId);

	if (!provider) {
		return c.text('Provider configuration not found for requested server', 404);
	}

	// Dynamic OAuth parameters
	const params = new URLSearchParams({
		client_id: provider.clientId,
		redirect_uri: redirect_uri || provider.redirectUri,
		response_type: 'code',
		scope: scopeMode[scopemode as keyof typeof scopeMode],
		state: JSON.stringify({
			originalState: state || '',
			serverId: provider.serverId,
		}),
		prompt: 'none',
	}).toString();

	return c.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

// OAuth Token Exchange Route
app.post('/token', async (c) => {
	const body = await c.req.parseBody();
	const code = body['code'] as string;
	const stateRaw = body['state'] as string;

	let serverId = body['server_id'] as string;

	if (stateRaw) {
		try {
			const parsedState = JSON.parse(stateRaw);
			serverId = parsedState.serverId || serverId;
		} catch {
			// Not a JSON state string, ignore
		}
	}

	const provider = await getProviderConfig(c.env, serverId);
	if (!provider) {
		return c.text('Provider credentials not found', 400);
	}

	const params = new URLSearchParams({
		client_id: provider.clientId,
		client_secret: provider.clientSecret,
		redirect_uri: body['redirect_uri'] as string || provider.redirectUri,
		code: code,
		grant_type: 'authorization_code',
		scope: 'identify email',
	}).toString();

	const r = await fetch('https://discord.com/api/v10/oauth2/token', {
		method: 'POST',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
	}).then((res) => res.json<RESTPostOAuth2AccessTokenResult>());

	if (r === null || !r['access_token']) {
		return new Response('Bad request or failed Discord token exchange.', { status: 400 });
	}

	const userInfo = await fetch('https://discord.com/api/v10/users/@me', {
		headers: {
			Authorization: 'Bearer ' + r['access_token'],
		},
	}).then((res) => res.json<APIUser & Record<string, unknown>>());

	if (!userInfo['verified']) return c.text('Bad request: User email not verified.', 400);

	let servers: string[] = [];
	const serverResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
		headers: {
			Authorization: 'Bearer ' + r['access_token'],
		},
	});

	if (serverResp.status === 200) {
		const serverJson = await serverResp.json<APIGuild[]>();
		servers = serverJson.map((item) => item.id);
	}

	const roleClaims: { [key: string]: string[] } = {};

	// Fetch roles specifically for the provider's bound server using its Bot Token
	if (provider.botToken && provider.serverId) {
		if (servers.includes(provider.serverId)) {
			const memberResp = await fetch(
				`https://discord.com/api/v10/guilds/${provider.serverId}/members/${userInfo['id']}`,
				{
					headers: {
						Authorization: 'Bot ' + provider.botToken,
					},
				}
			);
			if (memberResp.ok) {
				const memberJson = await memberResp.json<APIGuildMember>();
				roleClaims[`roles:${provider.serverId}`] = memberJson.roles;
			}
		}
	}

	const preferred_username = userInfo['username'];
	const displayName = userInfo['global_name'] ?? userInfo['username'];

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: provider.clientId,
		preferred_username,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		global_name: userInfo['global_name'],
		name: displayName,
		guilds: servers,
		server_id: provider.serverId,
	})
		.setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('1h')
		.setAudience(provider.clientId)
		.sign((await jwtPlugin.loadOrGenerateKeyPair(c.env.KV)).privateKey);

	return c.json({
		...r,
		scope: 'identify email',
		id_token: idToken,
	});
});

app.get('/jwks.json', async (c) => {
	const publicKey = (await jwtPlugin.loadOrGenerateKeyPair(c.env.KV)).publicKey;
	return c.json({
		keys: [
			{
				alg: 'RS256',
				kid: 'jwtRS256',
				...(await crypto.subtle.exportKey('jwk', publicKey)),
			},
		],
	});
});

// ==========================================
// ADMIN DASHBOARD & API (CF ACCESS PROTECTED)
// ==========================================

const adminApp = new Hono<{ Bindings: Bindings }>();
adminApp.use('*', cfAccessMiddleware);

// Admin REST API: List Providers
adminApp.get('/api/providers', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);

	const list = await c.env.KV.list({ prefix: 'provider:' });
	const providers: ServerProvider[] = [];

	for (const key of list.keys) {
		const raw = await c.env.KV.get(key.name);
		if (raw) {
			try {
				providers.push(JSON.parse(raw));
			} catch {
				// Ignore parse errors
			}
		}
	}

	return c.json(providers);
});

// Admin REST API: Save/Update Provider
adminApp.post('/api/providers', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);

	const body = await c.req.json<ServerProvider>();

	if (!body.serverId || !body.clientId || !body.clientSecret) {
		return c.json({ error: 'Missing required fields: serverId, clientId, clientSecret' }, 400);
	}

	const now = new Date().toISOString();
	const existingRaw = await c.env.KV.get(`provider:${body.serverId}`);
	const existing = existingRaw ? JSON.parse(existingRaw) : {};

	const provider: ServerProvider = {
		serverId: body.serverId,
		serverName: body.serverName || existing.serverName || 'Discord Server',
		clientId: body.clientId,
		clientSecret: body.clientSecret,
		botToken: body.botToken || '',
		redirectUri: body.redirectUri || '',
		createdAt: existing.createdAt || now,
		updatedAt: now,
	};

	await c.env.KV.put(`provider:${body.serverId}`, JSON.stringify(provider));
	return c.json({ success: true, provider });
});

// Admin REST API: Delete Provider
adminApp.delete('/api/providers/:serverId', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);
	const { serverId } = c.req.param();

	await c.env.KV.delete(`provider:${serverId}`);
	return c.json({ success: true, message: `Provider for server ${serverId} deleted.` });
});

// Admin Dashboard UI (Embedded Single Page App)
adminApp.get('/', (c) => {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Discord OIDC Multi-Tenant Admin</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen p-8 font-sans">
  <div class="max-w-5xl mx-auto">
    <div class="flex justify-between items-center mb-8 border-b border-slate-700 pb-4">
      <div>
        <h1 class="text-2xl font-bold text-indigo-400">Discord OIDC Providers (1:1 Multi-Tenant)</h1>
        <p class="text-slate-400 text-sm">Protected by Cloudflare Access Gateway</p>
      </div>
      <button onclick="openModal()" class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-medium transition shadow">
        + Add New Server Provider
      </button>
    </div>

    <!-- Provider List Table -->
    <div class="bg-slate-800 rounded-xl shadow overflow-hidden border border-slate-700">
      <table class="w-full text-left text-sm text-slate-300">
        <thead class="bg-slate-950/50 text-slate-400 uppercase text-xs">
          <tr>
            <th class="p-4">Server Name / ID</th>
            <th class="p-4">Client ID</th>
            <th class="p-4">Bot Token Configured</th>
            <th class="p-4">Redirect URI</th>
            <th class="p-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody id="provider-table" class="divide-y divide-slate-700">
          <tr><td colspan="5" class="p-4 text-center text-slate-500">Loading providers...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Modal -->
  <div id="modal" class="fixed inset-0 bg-black/70 hidden flex items-center justify-center p-4">
    <div class="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-md w-full shadow-2xl">
      <h2 id="modal-title" class="text-xl font-bold mb-4 text-indigo-400">Add Server Provider</h2>
      <form id="provider-form" onsubmit="saveProvider(event)" class="space-y-4 text-sm">
        <div>
          <label class="block text-slate-400 mb-1">Server ID (Discord Guild ID)</label>
          <input type="text" id="serverId" required class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Server Name (Optional)</label>
          <input type="text" id="serverName" placeholder="My Survival Server" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Discord Client ID</label>
          <input type="text" id="clientId" required class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Discord Client Secret</label>
          <input type="password" id="clientSecret" required class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Discord Bot Token</label>
          <input type="password" id="botToken" placeholder="Bot MTIz..." class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Redirect URI</label>
          <input type="text" id="redirectUri" placeholder="https://..." class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div class="flex justify-end gap-3 pt-4">
          <button type="button" onclick="closeModal()" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded text-slate-200">Cancel</button>
          <button type="submit" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded text-white font-medium">Save Provider</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    async function loadProviders() {
      const res = await fetch('/admin/api/providers');
      const data = await res.json();
      const tbody = document.getElementById('provider-table');
      if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500">No providers configured yet.</td></tr>';
        return;
      }
      tbody.innerHTML = data.map(p => \`
        <tr class="hover:bg-slate-750">
          <td class="p-4 font-medium text-white">\${p.serverName}<br><span class="text-xs text-slate-400">\${p.serverId}</span></td>
          <td class="p-4 font-mono text-xs text-indigo-300">\${p.clientId}</td>
          <td class="p-4">\${p.botToken ? '<span class="text-emerald-400">Yes</span>' : '<span class="text-amber-400">No</span>'}</td>
          <td class="p-4 text-xs text-slate-400">\${p.redirectUri || 'Default'}</td>
          <td class="p-4 text-right">
            <button onclick="deleteProvider('\${p.serverId}')" class="text-rose-400 hover:text-rose-300 font-medium">Delete</button>
          </td>
        </tr>
      \`).join('');
    }

    function openModal() {
      document.getElementById('provider-form').reset();
      document.getElementById('modal').classList.remove('hidden');
    }
    function closeModal() { document.getElementById('modal').classList.add('hidden'); }

    async function saveProvider(e) {
      e.preventDefault();
      const payload = {
        serverId: document.getElementById('serverId').value,
        serverName: document.getElementById('serverName').value,
        clientId: document.getElementById('clientId').value,
        clientSecret: document.getElementById('clientSecret').value,
        botToken: document.getElementById('botToken').value,
        redirectUri: document.getElementById('redirectUri').value,
      };
      await fetch('/admin/api/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      closeModal();
      loadProviders();
    }

    async function deleteProvider(serverId) {
      if (!confirm('Are you sure you want to delete this provider?')) return;
      await fetch('/admin/api/providers/' + serverId, { method: 'DELETE' });
      loadProviders();
    }

    loadProviders();
  </script>
</body>
</html>`;
	return c.html(html);
});

app.route('/admin', adminApp);

export default app;
