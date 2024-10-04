import { Hono } from "hono";
import { JwtPlugin } from "./plugins/jwk";
import * as jose from 'jose';

const jwtPlugin = new JwtPlugin();

export type Bindings = {
	DISCORD_CLIENT_ID: string;
	DISCORD_CLIENT_SECRET: string;
	DISCORD_CLIENT_TOKEN: string;
	DISCORD_REDIRECT_URI: string;
	SERVER_LIST: string;
	KV: KVNamespace
};

const app = new Hono<{
	Bindings: Bindings;
}>();

app.get("/", (c) => c.text("hello world!"));

app.get('/authorize/:scopemode', async (c) => {
	const { scopemode } = c.req.param();
	const { client_id, redirect_uri, state } = c.req.query();

	const scopeMode = {
		email: 'identify email',
		guilds: 'identify email guilds',
		roles: 'identify email guilds guilds.members.read',
	};

	if (!c.env.DISCORD_CLIENT_ID || !c.env.DISCORD_CLIENT_SECRET) {
		return c.text('No client id or client secret', 500);
	}

	if (
		client_id !== c.env.DISCORD_CLIENT_ID ||
		redirect_uri !== c.env.DISCORD_REDIRECT_URI ||
		scopemode === undefined ||
		!Object.keys(scopeMode).includes(scopemode)
		) {
		return c.text('Invalid parameters', 400);
	}

	const params = new URLSearchParams({
		client_id: c.env.DISCORD_CLIENT_ID as string,
		redirect_uri: c.env.DISCORD_REDIRECT_URI as string,
		response_type: 'code',
		scope: scopeMode[scopemode as keyof typeof scopeMode],
		state: state as string,
		prompt: 'none',
	}).toString();

	return c.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
})

app.post('/token', async (c) => {
	const body = await c.req.parseBody();
	const code = body['code'] as string;
	const params = new URLSearchParams({
		'client_id': c.env.DISCORD_CLIENT_ID,
		'client_secret': c.env.DISCORD_CLIENT_SECRET,
		'redirect_uri': c.env.DISCORD_REDIRECT_URI,
		'code': code,
		'grant_type': 'authorization_code',
		'scope': 'identify email'
	}).toString()

	const r: Record<string, any> = await fetch('https://discord.com/api/v10/oauth2/token', {
		method: 'POST',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	}).then(res => res.json())

	if (r === null) return new Response("Bad request.", { status: 400 })

	const userInfo: Record<string, any> = await fetch('https://discord.com/api/v10/users/@me', {
		headers: {
			'Authorization': 'Bearer ' + r['access_token'] as string
		}
	}).then(res => res.json())

	if (!userInfo['verified']) return c.text('Bad request.', 400)

	let servers = []

	const serverResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
		headers: {
			'Authorization': 'Bearer ' + r['access_token']
		}
	})

	if (serverResp.status === 200) {
		const serverJson: any[] = await serverResp.json()
		servers = serverJson.map(item => {
			return item['id']
		})
	}

	let roleClaims: any = {}


	if (c.env.DISCORD_CLIENT_TOKEN && c.env.SERVER_LIST) {
		await Promise.all(c.env.SERVER_LIST.split(',').map(async guildId => {
			if (servers.includes(guildId)) {
				let memberPromise = fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userInfo['id']}`, {
					headers: {
						'Authorization': 'Bot ' + c.env.DISCORD_CLIENT_TOKEN
					}
				})
				// i had issues doing this any other way?
				const memberResp = await memberPromise
				const memberJson: any = await memberResp.json()

				roleClaims[`roles:${guildId}`] = memberJson.roles
			}

		}
		))
	}

	let preferred_username = userInfo['username']

	if (userInfo['discriminator'] && userInfo['discriminator'] !== '0') {
		preferred_username += `#${userInfo['discriminator']}`
	}

	let displayName = userInfo['global_name'] ?? userInfo['username']

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: c.env.DISCORD_CLIENT_ID,
		preferred_username,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		global_name: userInfo['global_name'],
		name: displayName,
		guilds: servers
	})
		.setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('1h')
		.setAudience(c.env.DISCORD_CLIENT_ID)
		.sign((await jwtPlugin.loadOrGenerateKeyPair(c.env.KV)).privateKey)

	return c.json({
		...r,
		scope: 'identify email',
		id_token: idToken
	})
})

app.get('/jwk.json', async (c) => {
});

export default app;
