/** Single, session-scoped Switchboard connection for pi. */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { Agent, fetch as undiciFetch } from "undici";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export default function (pi: ExtensionAPI): void {
  let client: Client | undefined;
  let transport: StreamableHTTPClientTransport | undefined;
  let agent: Agent | undefined;
  let visible = new Set<string>();
  let catalogGeneration = 0;
  let refreshQueue = Promise.resolve();

  function settings(): { url: string; token: string } {
    const config = JSON.parse(readFileSync(process.env.SWITCHBOARD_PI_CONFIG ?? join(homedir(), ".pi/agent/switchboard.json"), "utf8"));
    const url = new URL(config.url);
    if (url.protocol !== "https:" || url.username || url.password) throw new Error("Switchboard requires a credential-free HTTPS URL");
    let token = process.env[config.token_env];
    if (!token) {
      const lines = readFileSync(join(homedir(), ".config/environment.d/92-switchboard.conf"), "utf8").split("\n");
      const line = lines.find((value) => value.startsWith(config.token_env + "="));
      if (line) token = JSON.parse(line.slice(config.token_env.length + 1));
    }
    if (!token) throw new Error("Switchboard credential is not available");
    return { url: url.href, token };
  }

  function caBundle(): string | undefined {
    const explicit = process.env.SWITCHBOARD_CA_CERTS;
    if (explicit !== undefined) {
      const bundle = readFileSync(explicit, "utf8");
      if (!bundle.trim()) throw new Error("Configured CA bundle is empty");
      return bundle;
    }
    for (const path of ["/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/certs/ca-certificates.crt"]) {
      if (!path) continue;
      try { return readFileSync(path, "utf8"); } catch { /* try the next system bundle */ }
    }
  }

  function invalidateCatalog(): void {
    const old = visible;
    visible = new Set<string>();
    catalogGeneration++;
    pi.setActiveTools(pi.getActiveTools().filter((name) => !old.has(name)));
  }

  async function refresh(expectedGeneration = catalogGeneration): Promise<void> {
    const connection = client;
    if (!connection || expectedGeneration !== catalogGeneration) return;
    const tools = [];
    let cursor: string | undefined;
    do {
      const result = await connection.listTools({ cursor });
      tools.push(...result.tools);
      cursor = result.nextCursor;
    } while (cursor);
    if (connection !== client || expectedGeneration !== catalogGeneration) return;
    const next = new Set(tools.map((tool) => tool.name));
    const old = visible;
    visible = next;
    const generation = ++catalogGeneration;
    for (const tool of tools) {
      pi.registerTool({
        name: tool.name,
        label: tool.title ?? tool.name,
        description: tool.description ?? tool.name,
        parameters: tool.inputSchema as any,
        async execute(_id, args, signal, _onUpdate, ctx) {
          const assertCurrent = () => {
            if (!visible.has(tool.name) || connection !== client || generation !== catalogGeneration) {
              throw new Error("Switchboard tool is no longer active; retry using the current tool catalog");
            }
          };
          assertCurrent();
          const readOnly = tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint !== true;
          if (!readOnly) {
            if (!ctx.hasUI || !(await ctx.ui.confirm("Switchboard tool approval", `Allow ${tool.name}? ${tool.description ?? "This tool may change upstream state."}`))) {
              throw new Error("Tool requires approval; no upstream call was made");
            }
          }
          // Confirmation can remain open while a notification replaces or
          // revokes this definition. Approval belongs to that exact catalog.
          assertCurrent();
          const result = await connection.callTool({ name: tool.name, arguments: args as Record<string, unknown> }, undefined, { signal, timeout: 120000 });
          // Preserve all MCP content and structured output in details. pi's
          // renderer handles text/images; other content remains serialized text.
          const content = result.content.map((item: any) => item.type === "text" || item.type === "image" ? item : { type: "text", text: JSON.stringify(item) });
          if (result.isError) throw new Error(content.map((item: any) => item.text ?? JSON.stringify(item)).join("\n"));
          return { content: content as any, details: { structuredContent: result.structuredContent } };
        },
      });
    }
    // Retain every non-Switchboard tool and remove only previously exposed tools.
    pi.setActiveTools([...new Set([...pi.getActiveTools().filter((name) => !old.has(name)), ...next])]);
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      const config = settings();
      agent = new Agent({ connect: { ca: caBundle() } });
      const dispatcher = agent;
      transport = new StreamableHTTPClientTransport(new URL(config.url), {
        requestInit: { headers: { Authorization: `Bearer ${config.token}` } },
        fetch: ((input, init) => {
          // Session replacement must not wait indefinitely for a remote DELETE.
          const signal = init?.method === "DELETE"
            ? AbortSignal.any([...(init.signal ? [init.signal] : []), AbortSignal.timeout(2000)])
            : init?.signal;
          return undiciFetch(input, { ...init, signal, dispatcher }) as unknown as Promise<Response>;
        }) as typeof fetch,
      });
      client = new Client({ name: "pi-switchboard", version: "0.1.0" });
      const connection = client;
      client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
        if (connection !== client) return;
        // The old catalog is uncertain as soon as a change is announced, even
        // if listing the replacement fails or takes time to complete.
        invalidateCatalog();
        const expectedGeneration = catalogGeneration;
        refreshQueue = refreshQueue.then(() => refresh(expectedGeneration)).catch(() => {
          if (connection === client && expectedGeneration === catalogGeneration) {
            ctx.ui.notify("Switchboard tools unavailable after refresh failure; reconnect or wait for a new catalog update", "error");
          }
        });
      });
      await client.connect(transport);
      await refresh();
    } catch {
      invalidateCatalog();
      ctx.ui.notify("Switchboard connection failed; check URL, credentials, and CA trust", "error");
    }
  });
  pi.on("session_shutdown", async () => {
    const connection = client;
    const stream = transport;
    const dispatcher = agent;
    client = undefined;
    transport = undefined;
    agent = undefined;
    invalidateCatalog();
    try { await stream?.terminateSession(); } catch { /* expired or unavailable */ }
    try {
      await connection?.close();
    } finally {
      // Shutdown cancels local outstanding I/O; it does not prove that an
      // already-submitted upstream mutation was rolled back.
      await dispatcher?.destroy();
    }
  });
}
