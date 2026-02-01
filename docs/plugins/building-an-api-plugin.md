# Building an OpenClaw API Plugin

This guide walks you through building an OpenClaw plugin that lets users connect their bot to your API. The plugin handles OAuth authentication and exposes tools the bot can call autonomously.

## Directory Structure

```
extensions/your-api/
├── package.json
├── index.ts          # Plugin entry point
├── oauth.ts          # OAuth flow (PKCE + localhost callback)
└── tools.ts          # Tools the bot can call
```

## package.json

```json
{
  "name": "@yourco/openclaw-your-api",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {},
  "devDependencies": {
    "openclaw": "workspace:*"
  },
  "openclaw": {
    "extensions": ["./index.ts"]
  }
}
```

Key points:

- The `openclaw.extensions` array points to your entry file(s).
- Put `openclaw` in `devDependencies` (not `dependencies`). Runtime resolves `openclaw/plugin-sdk` via jiti alias.
- Any third-party runtime dependencies (e.g., an SDK for your API) go in `dependencies`.

## index.ts — Plugin Entry Point

```typescript
import type { OpenClawPluginApi, ProviderAuthContext } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { runOAuthFlow } from "./oauth.js";
import { createTools } from "./tools.js";

export default {
  id: "your-api",
  name: "Your API",
  description: "Connect OpenClaw to Your API",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    // 1. Register the auth provider (OAuth flow)
    api.registerProvider({
      id: "your-api",
      label: "Your API",
      docsPath: "/providers/your-api",
      aliases: ["yourapi"],
      envVars: ["YOUR_API_KEY"],
      auth: [
        {
          id: "oauth",
          label: "OAuth Login",
          hint: "Authorize via browser",
          kind: "oauth",
          run: async (ctx: ProviderAuthContext) => {
            const spin = ctx.prompter.progress("Starting OAuth…");
            const result = await runOAuthFlow({
              isRemote: ctx.isRemote,
              openUrl: ctx.openUrl,
              prompt: async (msg) =>
                String(await ctx.prompter.text({ message: msg })),
            });
            spin.stop("Authorized");

            return {
              profiles: [
                {
                  profileId: `your-api:${result.email ?? "default"}`,
                  credential: {
                    type: "oauth",
                    provider: "your-api",
                    access: result.accessToken,
                    refresh: result.refreshToken,
                    expires: result.expiresAt,
                    email: result.email,
                  },
                },
              ],
            };
          },
        },
      ],
    });

    // 2. Register tools the bot can use
    api.registerTool((ctx) => createTools(ctx), {
      names: ["yourapi_search", "yourapi_create"],
    });
  },
};
```

The entry point does two things:

1. **Registers an auth provider** — defines the OAuth flow that runs once per user to obtain tokens.
2. **Registers tools** — functions the bot can call autonomously against your API.

You can also export a plain function instead of an object:

```typescript
export default function register(api: OpenClawPluginApi) {
  // api.registerProvider(...)
  // api.registerTool(...)
}
```

## oauth.ts — OAuth Flow

This implements OAuth 2.0 Authorization Code with PKCE. It supports two paths:

- **Automatic** — opens a browser, listens on a localhost callback port, captures the code.
- **Manual** — for headless/remote environments (SSH, containers) or when the localhost callback cannot bind (common on WSL2). The user opens the URL themselves and pastes the code back.

```typescript
import http from "node:http";
import crypto from "node:crypto";

const CLIENT_ID = "your-oauth-client-id";
const AUTH_URL = "https://yourapi.com/oauth/authorize";
const TOKEN_URL = "https://yourapi.com/oauth/token";
const CALLBACK_PORT = 51199;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;

export async function runOAuthFlow(opts: {
  isRemote: boolean;
  openUrl: (url: string) => Promise<void>;
  prompt: (msg: string) => Promise<string>;
}) {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const state = crypto.randomBytes(16).toString("hex");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  const authUrl =
    `${AUTH_URL}?` +
    new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      scope: "read write",
    });

  if (opts.isRemote) {
    // Manual flow — user pastes the full redirect URL (or code)
    const input = await opts.prompt(
      `Open this URL and paste the redirect URL (or code):\n${authUrl}`,
    );
    const parsed = parseCallbackInput(input);
    if (parsed.state && parsed.state !== state) {
      throw new Error("OAuth state mismatch");
    }
    return exchangeCode(parsed.code, verifier);
  }

  // Automatic flow — localhost callback captures the code
  try {
    const parsed = await listenForCallback(authUrl, opts.openUrl);
    if (parsed.state && parsed.state !== state) {
      throw new Error("OAuth state mismatch");
    }
    return exchangeCode(parsed.code, verifier);
  } catch {
    // Fallback: switch to manual if the callback server fails.
    const input = await opts.prompt(
      `Local callback failed. Paste the redirect URL (or code):\n${authUrl}`,
    );
    const parsed = parseCallbackInput(input);
    if (parsed.state && parsed.state !== state) {
      throw new Error("OAuth state mismatch");
    }
    return exchangeCode(parsed.code, verifier);
  }
}

async function listenForCallback(
  authUrl: string,
  openUrl: (url: string) => Promise<void>,
): Promise<{ code: string; state?: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url!, `http://localhost:${CALLBACK_PORT}`);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state") ?? undefined;
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<h1>Authorized. You can close this tab.</h1>");
      server.close();
      code ? resolve({ code, state }) : reject(new Error("No code in callback"));
    });
    server.listen(CALLBACK_PORT, () => {
      void openUrl(authUrl);
    });
  });
}

function parseCallbackInput(input: string): { code: string; state?: string } {
  const trimmed = input.trim();
  try {
    const url = new URL(trimmed);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") ?? undefined;
    if (!code) {
      throw new Error("Missing code parameter");
    }
    return { code, state };
  } catch {
    // Fallback: user pasted the raw code
    return { code: trimmed };
  }
}

async function exchangeCode(code: string, verifier: string) {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
    }),
  });
  const data = await res.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresAt: Date.now() + data.expires_in * 1000,
    email: data.email,
  };
}
```

### What you need on your side

Your API must implement a standard OAuth 2.0 provider with:

- An authorization endpoint (`/oauth/authorize`)
- A token endpoint (`/oauth/token`)
- PKCE support (recommended)
- Token refresh support (or long-lived access tokens)

### Alternative: Device Authorization Grant

If your users often run OpenClaw in headless environments, consider implementing the [Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628) (`grant_type=urn:ietf:params:oauth:grant-type:device_code`). The user gets a short URL and a code, approves on any device, and the bot polls until approval. No localhost callback needed. GitHub CLI uses this pattern.

## tools.ts — Tools the Bot Can Call

Tools are functions the bot invokes autonomously to interact with your API. Each tool has a name, description, parameter schema, and an `execute` function. To access auth profiles, register tools via a factory so you can use `ctx.agentDir` and `ctx.config`.

```typescript
import { Type } from "@sinclair/typebox";
import fs from "node:fs/promises";
import path from "node:path";

export function createTools(
  ctx: { config?: { auth?: { profiles?: Record<string, { provider?: string }> } }; agentDir?: string },
) {
  return [
    {
      name: "yourapi_search",
      description: "Search Your API for records",
      parameters: Type.Object({
        query: Type.String({ description: "Search query" }),
        limit: Type.Optional(
          Type.Number({ description: "Max results (default 10)" }),
        ),
      }),
      async execute(
        _id: string,
        params: { query: string; limit?: number },
      ) {
        const token = await getToken(ctx);
        const res = await fetch("https://yourapi.com/v1/search", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            q: params.query,
            limit: params.limit ?? 10,
          }),
        });
        const data = await res.json();
        return {
          content: [
            { type: "text", text: JSON.stringify(data, null, 2) },
          ],
        };
      },
    },
    {
      name: "yourapi_create",
      description: "Create a record in Your API",
      parameters: Type.Object({
        title: Type.String({ description: "Record title" }),
        body: Type.Optional(
          Type.String({ description: "Record body" }),
        ),
      }),
      async execute(
        _id: string,
        params: { title: string; body?: string },
      ) {
        const token = await getToken(ctx);
        const res = await fetch("https://yourapi.com/v1/records", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(params),
        });
        const data = await res.json();
        return {
          content: [
            { type: "text", text: `Created record: ${data.id}` },
          ],
        };
      },
    },
  ];
}

async function getToken(ctx: {
  config?: { auth?: { profiles?: Record<string, { provider?: string }> } };
  agentDir?: string;
}): Promise<string> {
  const profileId = Object.entries(ctx.config?.auth?.profiles ?? {}).find(
    ([, profile]) => profile?.provider === "your-api",
  )?.[0];
  if (!profileId) {
    throw new Error("No auth profile configured for your-api.");
  }
  if (!ctx.agentDir) {
    throw new Error("agentDir missing; tool must run in an agent context.");
  }
  const authPath = path.join(ctx.agentDir, "auth-profiles.json");
  const store = JSON.parse(await fs.readFile(authPath, "utf8")) as {
    profiles?: Record<
      string,
      { type?: string; access?: string; refresh?: string; token?: string; key?: string }
    >;
  };
  const cred = store.profiles?.[profileId];
  if (!cred) {
    throw new Error(`Missing credential for profile ${profileId}.`);
  }
  if (cred.type === "oauth") {
    const token = cred.access?.trim();
    if (!token) {
      throw new Error(`OAuth access token missing for profile ${profileId}.`);
    }
    return token;
  }
  if (cred.type === "token") {
    const token = cred.token?.trim();
    if (!token) {
      throw new Error(`Token missing for profile ${profileId}.`);
    }
    return token;
  }
  if (cred.type === "api_key") {
    const token = cred.key?.trim();
    if (!token) {
      throw new Error(`API key missing for profile ${profileId}.`);
    }
    return token;
  }
  throw new Error(`Unsupported credential type for profile ${profileId}.`);
}
```

### Tool schema guidelines

- Use `Type.Object` for the top-level parameter schema.
- Use `Type.Optional(...)` for optional fields (not `| null`).
- Avoid `Type.Union` — use `Type.Unsafe` with `enum` for string enums instead.
- Avoid using `format` as a property name (some validators treat it as reserved).

## Other Registration Options

Beyond `registerProvider` and `registerTool`, the plugin API offers:

| Method | Purpose | Example use case |
|---|---|---|
| `registerTool()` | Functions the bot can call | Search, create, update records |
| `registerProvider()` | OAuth/auth flow (runs once per user) | User login to your platform |
| `registerHook()` / `on()` | React to lifecycle events | Inject context before each conversation |
| `registerCli()` | Add CLI subcommands | `openclaw yourapi status` |
| `registerHttpRoute()` | Receive webhooks from your API | Real-time event notifications |
| `registerService()` | Background process with start/stop | Polling, long-lived connections |
| `registerChannel()` | Full messaging channel | If your platform has a chat surface |
| `registerCommand()` | Simple slash command | `/yourapi-status` toggle |
| `registerGatewayMethod()` | Gateway RPC method | Custom gateway endpoints |

### Hooks example — inject context before each conversation

If you need OAuth tokens outside tools, pass `config` + an agent dir (for example from `OPENCLAW_AGENT_DIR`) into the same helper.

```typescript
api.on("before_agent_start", async (event) => {
  if (!event.prompt) return;

  const agentDir = process.env.OPENCLAW_AGENT_DIR || process.env.PI_CODING_AGENT_DIR;
  const token = await getToken({ config: api.config, agentDir });
  const res = await fetch("https://yourapi.com/v1/context", {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json();

  return {
    prependContext: `<your-api-context>\n${JSON.stringify(data)}\n</your-api-context>`,
  };
});
```

### CLI commands example

```typescript
api.registerCli(
  ({ program }) => {
    const cmd = program
      .command("yourapi")
      .description("Your API plugin commands");

    cmd
      .command("status")
      .description("Check connection status")
      .action(async () => {
        const agentDir = process.env.OPENCLAW_AGENT_DIR || process.env.PI_CODING_AGENT_DIR;
        const token = await getToken({ config: api.config, agentDir });
        const res = await fetch("https://yourapi.com/v1/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        console.log(`Connected as: ${data.email}`);
      });
  },
  { commands: ["yourapi"] },
);
```

### Webhook receiver example

```typescript
api.registerHttpRoute({
  path: "/webhooks/yourapi",
  handler: async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    const event = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    api.logger.info?.(`Received webhook: ${event.type}`);
    // Process the event...
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/plain");
    res.end("ok");
  },
});
```

## End-User Experience

Once your plugin is published:

1. User installs: `npm i @yourco/openclaw-your-api`
2. Onboarding triggers the OAuth flow automatically (or user runs `openclaw models auth login --provider your-api`)
3. User clicks one link, approves on your consent screen — done
4. From that point on, the bot calls your API tools autonomously with no further human intervention
5. Tokens refresh on-demand when OpenClaw can refresh them; otherwise re-auth or refresh inside your plugin

## Available Lifecycle Hooks

```
before_agent_start    — Before the agent processes a message
agent_end             — After the agent finishes
message_received      — Incoming message from a channel
message_sending       — Before a message is sent
message_sent          — After a message is sent
before_tool_call      — Before a tool executes
after_tool_call       — After a tool executes
session_start         — New session begins
session_end           — Session ends
gateway_start         — Gateway starts up
gateway_stop          — Gateway shuts down
before_compaction     — Before context compaction
after_compaction      — After context compaction
tool_result_persist   — When tool results are saved
```

## Credential Storage

Credentials returned from your auth flow are stored in the auth profile store at:

- Default: `~/.openclaw/agents/<agentId>/agent/auth-profiles.json`
- Override: `$OPENCLAW_AGENT_DIR/auth-profiles.json`

Supported credential types:

- **`oauth`** — access token, refresh token, expiry, email
- **`api_key`** — static API key
- **`token`** — bearer token with optional expiry
