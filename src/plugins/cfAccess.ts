import { Context, Next } from 'hono';
import * as jose from 'jose';

export async function cfAccessMiddleware(c: Context, next: Next) {
	const jwtToken = c.req.header('Cf-Access-Jwt-Assertion');

	const teamDomain = c.env.CF_ACCESS_TEAM_DOMAIN;
	const expectedAud = c.env.CF_ACCESS_AUD;

	// If Cloudflare Access configuration is not set up, block access for security
	if (!teamDomain || !expectedAud) {
		// If running locally or without CF Access configured, check for emergency bypass header or reject
		if (c.env.ENVIRONMENT === 'development') {
			return await next();
		}
		return c.text('Cloudflare Access is not configured on this Worker.', 500);
	}

	if (!jwtToken) {
		return c.text('Unauthorized: Missing Cloudflare Access JWT Assertion header', 401);
	}

	try {
		const certsUrl = `https://${teamDomain}.cloudflareaccess.com/cdn-cgi/access/certs`;
		const JWKS = jose.createRemoteJWKSet(new URL(certsUrl));

		const { payload } = await jose.jwtVerify(jwtToken, JWKS, {
			issuer: `https://${teamDomain}.cloudflareaccess.com`,
			audience: expectedAud,
		});

		c.set('cf_access_user', payload.email);
		await next();
	} catch (err: unknown) {
		const errorMessage = err instanceof Error ? err.message : 'Unknown error';
		return c.text(`Forbidden: Invalid Access JWT (${errorMessage})`, 403);
	}
}
