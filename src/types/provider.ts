export interface BotGroup {
  groupId: string;          // Unique group identifier (e.g., "vortexia-network")
  groupName: string;        // Human readable group name
  clientId: string;          // Discord OAuth Client ID
  clientSecret: string;      // Discord OAuth Client Secret
  botToken: string;          // Shared Discord Bot Token
  redirectUri: string;       // OAuth Redirect URI
  serverIds: string[];       // Array of bound Discord Guild IDs
  createdAt?: string;
  updatedAt?: string;
}

// Backward compatibility alias
export type ServerProvider = BotGroup;
