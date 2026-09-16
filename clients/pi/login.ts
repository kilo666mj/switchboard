import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import { Agent, fetch as undiciFetch } from "undici";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { FileOAuthProvider, loadSettings } from "./oauth.ts";

function caBundle(): string | undefined {
  const explicit = process.env.SWITCHBOARD_CA_CERTS;
  if (explicit !== undefined) {
    const bundle = readFileSync(explicit, "utf8");
    if (!bundle.trim()) throw new Error("Configured CA bundle is empty");
    return bundle;
  }
  for (const path of ["/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/certs/ca-certificates.crt"]) {
    try { return readFileSync(path, "utf8"); } catch { /* try the next system bundle */ }
  }
}

const settings = loadSettings();
const callback = new URL(settings.redirectUrl);
const agent = new Agent({ connect: { ca: caBundle() } });
const fetchFn = ((input: URL | RequestInfo, init?: RequestInit) => undiciFetch(input as any, { ...init, dispatcher: agent }) as unknown as Promise<Response>) as typeof fetch;
let authorizationURL: URL | undefined;
let resolveCode!: (code: string) => void;
let rejectCode!: (error: Error) => void;
const code = new Promise<string>((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
const provider = new FileOAuthProvider(settings, (url) => { authorizationURL = url; });

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", settings.redirectUrl);
  if (request.method !== "GET" || url.pathname !== callback.pathname) {
    response.writeHead(404).end("Not found");
    return;
  }
  if (url.searchParams.get("state") !== provider.expectedState) {
    response.writeHead(400).end("Invalid OAuth state");
    rejectCode(new Error("OAuth state mismatch"));
    return;
  }
  const error = url.searchParams.get("error");
  const value = url.searchParams.get("code");
  if (error || !value) {
    response.writeHead(400).end("Authorization failed");
    rejectCode(new Error(error ?? "authorization code missing"));
    return;
  }
  response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" }).end("Pi Switchboard authorization complete. You can close this tab.");
  resolveCode(value);
});

try {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(callback.port), callback.hostname, resolve);
  });
  const result = await auth(provider, { serverUrl: settings.url, scope: settings.scopes.join(" "), fetchFn });
  if (result !== "REDIRECT" || !authorizationURL) throw new Error("Pocket ID did not start an authorization flow");
  console.log("Open this URL to authorize Pi Switchboard:\n" + authorizationURL.toString());
  const timeout = setTimeout(() => rejectCode(new Error("authorization timed out")), 5 * 60 * 1000);
  const authorizationCode = await code;
  clearTimeout(timeout);
  const completed = await auth(provider, { serverUrl: settings.url, authorizationCode, scope: settings.scopes.join(" "), fetchFn });
  if (completed !== "AUTHORIZED") throw new Error("Pocket ID token exchange did not complete");
  console.log("Pi Switchboard OAuth login succeeded.");
} finally {
  server.close();
  await agent.close();
}
