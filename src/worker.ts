import { Hono } from "hono";
import { JwtPlugin } from "./plugins/jwk";
import { cfAccessMiddleware } from "./plugins/cfAccess";
import { BotGroup } from "./types/provider";
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
 * Helper to fetch BotGroup config by serverId or groupId from KV or fallback to ENV.
 */
async function getBotGroup(env: Bindings, targetId?: string): Promise<{ group: BotGroup; matchedServerId: string } | null> {
	if (env.KV) {
		// 1. Direct group lookup if targetId starts with "group:" or exact groupId
		if (targetId) {
			const directGroupRaw = await env.KV.get(`group:${targetId}`);
			if (directGroupRaw) {
				try {
					const group = JSON.parse(directGroupRaw) as BotGroup;
					return { group, matchedServerId: group.serverIds?.[0] || targetId };
				} catch (e) {
					console.error(`Failed to parse group JSON for ${targetId}`, e);
				}
			}
		}

		// 2. Scan all groups to find one containing targetId in serverIds
		const list = await env.KV.list({ prefix: 'group:' });
		for (const key of list.keys) {
			const raw = await env.KV.get(key.name);
			if (raw) {
				try {
					const group = JSON.parse(raw) as BotGroup;
					if (targetId && group.serverIds?.includes(targetId)) {
						return { group, matchedServerId: targetId };
					}
					if (group.groupId === targetId) {
						return { group, matchedServerId: group.serverIds?.[0] || targetId };
					}
				} catch {
					// Ignore invalid JSON
				}
			}
		}

		// 3. Fallback backward compatibility lookup for old "provider:serverId" keys
		if (targetId) {
			const oldProviderRaw = await env.KV.get(`provider:${targetId}`);
			if (oldProviderRaw) {
				try {
					const oldP = JSON.parse(oldProviderRaw);
					const group: BotGroup = {
						groupId: oldP.serverId,
						groupName: oldP.serverName || 'Legacy Provider',
						clientId: oldP.clientId,
						clientSecret: oldP.clientSecret,
						botToken: oldP.botToken || '',
						redirectUri: oldP.redirectUri || '',
						serverIds: [oldP.serverId],
					};
					return { group, matchedServerId: targetId };
				} catch {
					// Ignore invalid legacy provider format
				}
			}
		}
	}

	// 4. Fallback to static env configuration if available
	if (env.DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET) {
		const staticServerList = env.SERVER_LIST ? env.SERVER_LIST.split(',') : [];
		const fallbackServerId = targetId || staticServerList[0] || 'default';
		return {
			group: {
				groupId: 'default',
				groupName: 'Default Environment Group',
				clientId: env.DISCORD_CLIENT_ID,
				clientSecret: env.DISCORD_CLIENT_SECRET,
				botToken: env.DISCORD_CLIENT_TOKEN || '',
				redirectUri: env.DISCORD_REDIRECT_URI || '',
				serverIds: staticServerList.length > 0 ? staticServerList : [fallbackServerId],
			},
			matchedServerId: fallbackServerId,
		};
	}

	return null;
}

// OAuth Authorize Route
app.get('/authorize/:scopemode', async (c) => {
	const { scopemode } = c.req.param();
	const { redirect_uri, state, server_id, group_id } = c.req.query();

	const scopeMode = {
		email: 'identify email',
		guilds: 'identify email guilds',
		roles: 'identify email guilds guilds.members.read',
	};

	if (scopemode === undefined || !Object.keys(scopeMode).includes(scopemode)) {
		return c.text('Invalid scope mode', 400);
	}

	const targetId = server_id || group_id || (c.req.query('server') as string);
	const resolved = await getBotGroup(c.env, targetId);

	if (!resolved) {
		return c.text('Bot Group or Server Provider configuration not found', 404);
	}

	const { group, matchedServerId } = resolved;

	const params = new URLSearchParams({
		client_id: group.clientId,
		redirect_uri: redirect_uri || group.redirectUri,
		response_type: 'code',
		scope: scopeMode[scopemode as keyof typeof scopeMode],
		state: JSON.stringify({
			originalState: state || '',
			groupId: group.groupId,
			serverId: matchedServerId,
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
	let groupId = body['group_id'] as string;

	if (stateRaw) {
		try {
			const parsedState = JSON.parse(stateRaw);
			serverId = parsedState.serverId || serverId;
			groupId = parsedState.groupId || groupId;
		} catch {
			// Ignore non-JSON state
		}
	}

	const targetId = serverId || groupId;
	const resolved = await getBotGroup(c.env, targetId);
	if (!resolved) {
		return c.text('Bot Group credentials not found', 400);
	}

	const { group } = resolved;
	const targetServerId = serverId || resolved.matchedServerId;

	const params = new URLSearchParams({
		client_id: group.clientId,
		client_secret: group.clientSecret,
		redirect_uri: (body['redirect_uri'] as string) || group.redirectUri,
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

	// Query roles for the target server if the bot token is provided
	if (group.botToken && targetServerId) {
		if (servers.includes(targetServerId)) {
			const memberResp = await fetch(
				`https://discord.com/api/v10/guilds/${targetServerId}/members/${userInfo['id']}`,
				{
					headers: {
						Authorization: 'Bot ' + group.botToken,
					},
				}
			);
			if (memberResp.ok) {
				const memberJson = await memberResp.json<APIGuildMember>();
				roleClaims[`roles:${targetServerId}`] = memberJson.roles;
			}
		}
	}

	const preferred_username = userInfo['username'];
	const displayName = userInfo['global_name'] ?? userInfo['username'];

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: group.clientId,
		preferred_username,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		global_name: userInfo['global_name'],
		name: displayName,
		guilds: servers,
		group_id: group.groupId,
		server_id: targetServerId,
	})
		.setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('1h')
		.setAudience(group.clientId)
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
// ADMIN DASHBOARD & REST API (CF ACCESS PROTECTED)
// ==========================================

const adminApp = new Hono<{ Bindings: Bindings }>();
adminApp.use('*', cfAccessMiddleware);

// Admin REST API: List Groups
adminApp.get('/api/groups', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);

	const list = await c.env.KV.list({ prefix: 'group:' });
	const groups: BotGroup[] = [];

	for (const key of list.keys) {
		const raw = await c.env.KV.get(key.name);
		if (raw) {
			try {
				groups.push(JSON.parse(raw));
			} catch {
				// Ignore JSON errors
			}
		}
	}

	return c.json(groups);
});

// Admin REST API: Save/Update Group
adminApp.post('/api/groups', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);

	const body = await c.req.json<BotGroup>();

	if (!body.groupId || !body.clientId || !body.clientSecret) {
		return c.json({ error: 'Missing required fields: groupId, clientId, clientSecret' }, 400);
	}

	const now = new Date().toISOString();
	const existingRaw = await c.env.KV.get(`group:${body.groupId}`);
	const existing = existingRaw ? JSON.parse(existingRaw) : {};

	// Clean & deduplicate serverIds
	const serverIds = Array.isArray(body.serverIds)
		? [...new Set(body.serverIds.map((id) => id.trim()).filter(Boolean))]
		: existing.serverIds || [];

	const group: BotGroup = {
		groupId: body.groupId.trim(),
		groupName: body.groupName || existing.groupName || 'Bot Group',
		clientId: body.clientId.trim(),
		clientSecret: body.clientSecret.trim(),
		botToken: body.botToken ? body.botToken.trim() : existing.botToken || '',
		redirectUri: body.redirectUri ? body.redirectUri.trim() : existing.redirectUri || '',
		serverIds,
		createdAt: existing.createdAt || now,
		updatedAt: now,
	};

	await c.env.KV.put(`group:${group.groupId}`, JSON.stringify(group));
	return c.json({ success: true, group });
});

// Admin REST API: Delete Group
adminApp.delete('/api/groups/:groupId', async (c) => {
	if (!c.env.KV) return c.json({ error: 'KV Namespace not configured' }, 500);
	const { groupId } = c.req.param();

	await c.env.KV.delete(`group:${groupId}`);
	return c.json({ success: true, message: `Group ${groupId} deleted.` });
});

// Admin Dashboard UI (Embedded Single Page App)
adminApp.get('/', (c) => {
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Discord OIDC - Bot Groups Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-6 font-sans">
  <div class="max-w-6xl mx-auto">
    <!-- Header -->
    <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 pb-4 border-b border-slate-800 gap-4">
      <div>
        <h1 class="text-2xl font-bold text-indigo-400 flex items-center gap-2">
          <span>🤖</span> Discord Bot Groups Manager
        </h1>
        <p class="text-slate-400 text-sm mt-1">Multi-Tenant 1 Bot Group ──► Multi-Server Mapping (Protected by Cloudflare Access)</p>
      </div>
      <button onclick="openModal()" class="bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2.5 rounded-xl font-medium transition shadow-lg shadow-indigo-600/20 flex items-center gap-2">
        <span>+</span> Add Bot Group
      </button>
    </div>

    <!-- Groups Container -->
    <div id="groups-container" class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div class="col-span-full text-center py-12 text-slate-500">Loading Bot Groups...</div>
    </div>
  </div>

  <!-- Group Modal -->
  <div id="modal" class="fixed inset-0 bg-black/80 backdrop-blur-sm hidden flex items-center justify-center p-4 z-50">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full shadow-2xl">
      <div class="flex justify-between items-center mb-6">
        <h2 id="modal-title" class="text-xl font-bold text-indigo-400">Add Bot Group</h2>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white text-xl">&times;</button>
      </div>
      <form id="group-form" onsubmit="saveGroup(event)" class="space-y-4 text-sm">
        <div>
          <label class="block text-slate-400 mb-1 font-medium">Group ID (Unique Slug)</label>
          <input type="text" id="groupId" required placeholder="e.g. vortexia-network" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1 font-medium">Group Name</label>
          <input type="text" id="groupName" required placeholder="e.g. Vortexia Minecraft Cluster" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Discord Client ID</label>
            <input type="text" id="clientId" required placeholder="123456789..." class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 font-mono text-xs">
          </div>
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Discord Client Secret</label>
            <input type="password" id="clientSecret" required placeholder="••••••••" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 font-mono text-xs">
          </div>
        </div>
        <div>
          <label class="block text-slate-400 mb-1 font-medium">Discord Bot Token (Shared)</label>
          <input type="password" id="botToken" placeholder="Bot MTIz..." class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 font-mono text-xs">
        </div>
        <div>
          <label class="block text-slate-400 mb-1 font-medium">Redirect URI</label>
          <input type="text" id="redirectUri" placeholder="https://auth.domain.com/token" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 font-mono text-xs">
        </div>
        <div>
          <label class="block text-slate-400 mb-1 font-medium">Bound Server IDs (Comma separated)</label>
          <textarea id="serverIds" rows="2" placeholder="112233445566778899, 998877665544332211" class="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:outline-none focus:border-indigo-500 font-mono text-xs"></textarea>
          <p class="text-xs text-slate-500 mt-1">Nhiều Server ID phân cách bằng dấu phẩy (,)</p>
        </div>
        <div class="flex justify-end gap-3 pt-4 border-t border-slate-800">
          <button type="button" onclick="closeModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-xl text-slate-300 font-medium">Cancel</button>
          <button type="submit" class="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-white font-medium shadow-lg shadow-indigo-600/20">Save Group</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let rawGroups = [];

    async function loadGroups() {
      const res = await fetch('/admin/api/groups');
      rawGroups = await res.json();
      const container = document.getElementById('groups-container');
      
      if (!rawGroups.length) {
        container.innerHTML = \`<div class="col-span-full bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-500">
          Chưa có Bot Group nào. Bấm <b>+ Add Bot Group</b> để tạo mới.
        </div>\`;
        return;
      }

      container.innerHTML = rawGroups.map(g => \`
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition">
          <div>
            <div class="flex justify-between items-start">
              <div>
                <h3 class="text-lg font-bold text-white flex items-center gap-2">\${g.groupName}</h3>
                <span class="text-xs font-mono text-indigo-400 bg-indigo-950/60 border border-indigo-800/50 px-2 py-0.5 rounded-md mt-1 inline-block">ID: \${g.groupId}</span>
              </div>
              <span class="text-xs font-medium px-2.5 py-1 rounded-full \${g.botToken ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/50' : 'bg-amber-950/80 text-amber-400 border border-amber-800/50'}">
                \${g.botToken ? '✓ Bot Token Active' : '⚠ No Bot Token'}
              </span>
            </div>

            <div class="mt-4 space-y-2 text-xs text-slate-400">
              <div class="flex justify-between border-b border-slate-800/60 pb-1.5">
                <span>Client ID:</span>
                <span class="font-mono text-slate-200">\${g.clientId}</span>
              </div>
              <div class="flex justify-between border-b border-slate-800/60 pb-1.5">
                <span>Redirect URI:</span>
                <span class="font-mono text-slate-200 truncate max-w-[200px]">\${g.redirectUri || 'Default'}</span>
              </div>
            </div>

            <!-- Server IDs Badges -->
            <div class="mt-4">
              <label class="block text-xs font-medium text-slate-400 mb-2">Bound Server IDs (\${g.serverIds?.length || 0}):</label>
              <div class="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
                \${(g.serverIds && g.serverIds.length) ? g.serverIds.map(sid => \`
                  <span class="bg-slate-950 border border-slate-800 text-slate-300 font-mono text-[11px] px-2 py-0.5 rounded-md shadow-sm">\${sid}</span>
                \`).join('') : '<span class="text-slate-600 text-xs italic">No servers bound</span>'}
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex justify-end gap-2 pt-4 border-t border-slate-800/80 text-xs font-medium">
            <button onclick="editGroup('\${g.groupId}')" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-indigo-300 rounded-lg transition">Edit</button>
            <button onclick="duplicateGroup('\${g.groupId}')" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded-lg transition">Duplicate</button>
            <button onclick="deleteGroup('\${g.groupId}')" class="px-3 py-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-400 border border-rose-900/50 rounded-lg transition">Delete</button>
          </div>
        </div>
      \`).join('');
    }

    function openModal(title = 'Add Bot Group') {
      document.getElementById('modal-title').innerText = title;
      document.getElementById('group-form').reset();
      document.getElementById('groupId').disabled = false;
      document.getElementById('modal').classList.remove('hidden');
    }
    function closeModal() { document.getElementById('modal').classList.add('hidden'); }

    function editGroup(groupId) {
      const g = rawGroups.find(item => item.groupId === groupId);
      if (!g) return;
      openModal('Edit Bot Group');
      document.getElementById('groupId').value = g.groupId;
      document.getElementById('groupId').disabled = true;
      document.getElementById('groupName').value = g.groupName || '';
      document.getElementById('clientId').value = g.clientId || '';
      document.getElementById('clientSecret').value = g.clientSecret || '';
      document.getElementById('botToken').value = g.botToken || '';
      document.getElementById('redirectUri').value = g.redirectUri || '';
      document.getElementById('serverIds').value = (g.serverIds || []).join(', ');
    }

    function duplicateGroup(groupId) {
      const g = rawGroups.find(item => item.groupId === groupId);
      if (!g) return;
      openModal('Duplicate Bot Group');
      document.getElementById('groupId').value = g.groupId + '-copy';
      document.getElementById('groupName').value = (g.groupName || '') + ' (Copy)';
      document.getElementById('clientId').value = g.clientId || '';
      document.getElementById('clientSecret').value = g.clientSecret || '';
      document.getElementById('botToken').value = g.botToken || '';
      document.getElementById('redirectUri').value = g.redirectUri || '';
      document.getElementById('serverIds').value = (g.serverIds || []).join(', ');
    }

    async function saveGroup(e) {
      e.preventDefault();
      const rawServers = document.getElementById('serverIds').value;
      const serverIds = rawServers.split(',').map(s => s.trim()).filter(Boolean);

      const payload = {
        groupId: document.getElementById('groupId').value,
        groupName: document.getElementById('groupName').value,
        clientId: document.getElementById('clientId').value,
        clientSecret: document.getElementById('clientSecret').value,
        botToken: document.getElementById('botToken').value,
        redirectUri: document.getElementById('redirectUri').value,
        serverIds: serverIds,
      };

      await fetch('/admin/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      closeModal();
      loadGroups();
    }

    async function deleteGroup(groupId) {
      if (!confirm(\`Are you sure you want to delete group "\${groupId}"?\`)) return;
      await fetch('/admin/api/groups/' + groupId, { method: 'DELETE' });
      loadGroups();
    }

    loadGroups();
  </script>
</body>
</html>`;
	return c.html(html);
});

app.route('/admin', adminApp);

export default app;
