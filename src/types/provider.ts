export interface ServerProvider {
  serverId: string;          // Discord Guild ID
  serverName: string;        // Human readable name 
  clientId: string;          // Discord OAuth Client ID
  clientSecret: string;      // Discord OAuth Client Secret
  botToken: string;          // Discord Bot Token
  redirectUri: string;       // OAuth Redirect URI configured in Discord Dev Portal
  createdAt?: string;
  updatedAt?: string;
}
