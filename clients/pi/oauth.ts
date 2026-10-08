import type { OAuthClientProvider, OAuthDiscoveryState } from "@modelcontextprotocol/sdk/client/auth.js";
import type { AuthorizationServerMetadata, OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

export type SwitchboardSettings = {
  url: string;
  issuer: string;
  clientId: string;
  redirectUrl: string;
  scopes: string[];
  tokenFile: string;
};

const defaultConfig = join(homedir(), ".pi/agent/switchboard.json");
const defaultTokenFile = join(homedir(), ".pi/agent/switchboard-oauth.json");
const requiredScopes = ["openid", "groups", "mcp:connect", "tools:read", "tools:write", "offline_access"];

function exactURL(value: unknown, protocol: string): string {
  if (typeof value !== "string" || value.trim() !== value) throw new Error("invalid Switchboard OAuth URL");
  const parsed = new URL(value);
  if (parsed.protocol !== protocol || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("invalid Switchboard OAuth URL");
  return parsed.href;
}

export function loadSettings(): SwitchboardSettings {
  const path = process.env.SWITCHBOARD_PI_CONFIG ?? defaultConfig;
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const url = exactURL(raw.url, "https:");
  const issuer = exactURL(raw.issuer, "https:").replace(/\/$/, "");
  const redirectUrl = exactURL(raw.redirect_url, "http:");
  if (redirectUrl !== "http://127.0.0.1:18104/callback") throw new Error("unexpected Pi OAuth callback URL");
  if (raw.client_id !== "pi-switchboard") throw new Error("unexpected Pi OAuth client ID");
  if (!Array.isArray(raw.scopes) || raw.scopes.some((scope: unknown) => typeof scope !== "string" || !scope)) throw new Error("invalid Pi OAuth scopes");
  const scopes = [...new Set<string>(raw.scopes)];
  if (requiredScopes.some((scope) => !scopes.includes(scope))) throw new Error("Pi OAuth configuration is missing a required scope");
  return { url, issuer, clientId: raw.client_id, redirectUrl, scopes, tokenFile: process.env.SWITCHBOARD_PI_TOKEN_FILE ?? defaultTokenFile };
}

function sameIssuer(a: unknown, b: string): boolean {
  if (typeof a !== "string") return false;
  try { return new URL(a).href.replace(/\/$/, "") === new URL(b).href.replace(/\/$/, ""); }
  catch { return false; }
}

// Discovery, client information, and tokens are all pinned to the configured
// issuer. Resource metadata from the MCP server can never redirect credentials
// to another authorization server.
export class FileOAuthProvider implements OAuthClientProvider {
  private verifier = "";
  private metadata: AuthorizationServerMetadata | undefined;
  readonly expectedState = randomBytes(24).toString("base64url");

  constructor(readonly settings: SwitchboardSettings, private readonly onRedirect: (url: URL) => void | Promise<void>) {}

  get redirectUrl(): string { return this.settings.redirectUrl; }
  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "Pi Switchboard",
      redirect_uris: [this.settings.redirectUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: this.settings.scopes.join(" "),
    };
  }
  state(): string { return this.expectedState; }
  clientInformation(): OAuthClientInformationMixed {
    return { client_id: this.settings.clientId, token_endpoint_auth_method: "none", issuer: this.settings.issuer };
  }
  discoveryState(): OAuthDiscoveryState {
    return { authorizationServerUrl: this.settings.issuer, authorizationServerMetadata: this.metadata };
  }
  saveDiscoveryState(state: OAuthDiscoveryState): void {
    if (!sameIssuer(state.authorizationServerUrl, this.settings.issuer) || !sameIssuer(state.authorizationServerMetadata?.issuer, this.settings.issuer)) {
      throw new Error("OAuth discovery returned an unexpected issuer");
    }
    this.metadata = state.authorizationServerMetadata;
  }
  tokens(): OAuthTokens | undefined {
    let stored: OAuthTokens;
    try { stored = JSON.parse(readFileSync(this.settings.tokenFile, "utf8")); }
    catch (error: any) { if (error?.code === "ENOENT") return undefined; throw error; }
    // Files written before issuer binding were obtained for the configured
    // issuer and, with discovery pinned, can only be presented to it.
    if (stored.issuer == null) return { ...stored, issuer: this.settings.issuer };
    return sameIssuer(stored.issuer, this.settings.issuer) ? stored : undefined;
  }
  saveTokens(tokens: OAuthTokens): void {
    if (!sameIssuer(tokens.issuer, this.settings.issuer)) throw new Error("refusing OAuth tokens from an unexpected issuer");
    const current = this.tokens();
    const saved = current?.refresh_token && !tokens.refresh_token ? { ...tokens, refresh_token: current.refresh_token } : tokens;
    mkdirSync(dirname(this.settings.tokenFile), { recursive: true, mode: 0o700 });
    const temporary = `${this.settings.tokenFile}.${process.pid}.tmp`;
    writeFileSync(temporary, JSON.stringify(saved), { mode: 0o600, flag: "wx" });
    renameSync(temporary, this.settings.tokenFile);
    chmodSync(this.settings.tokenFile, 0o600);
  }
  redirectToAuthorization(url: URL): void | Promise<void> { return this.onRedirect(url); }
  saveCodeVerifier(verifier: string): void { this.verifier = verifier; }
  codeVerifier(): string {
    if (!this.verifier) throw new Error("OAuth PKCE verifier is unavailable");
    return this.verifier;
  }
}
