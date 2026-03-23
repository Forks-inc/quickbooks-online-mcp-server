import express from "express";
import cors from "cors";
import crypto from "crypto";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// ─── In-Memory OAuth2 Storage ───────────────────────────────────────
const oauth_clients: Record<string, { client_secret: string, client_name: string, redirect_uris: string[], grant_types: string[], token_endpoint_auth_method: string }> = {};
const auth_codes: Record<string, { client_id: string, redirect_uri: string, code_challenge: string, code_challenge_method: string, scope: string, expires: number }> = {};
const access_tokens: Record<string, { client_id: string, scope: string, expires: number }> = {};
const refresh_tokens: Record<string, { client_id: string, scope: string, access_token: string }> = {};

function generateToken(bytes = 36): string {
    return crypto.randomBytes(bytes).toString("base64url");
}

function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
    const hash = crypto.createHash("sha256").update(codeVerifier).digest();
    const computed = hash.toString("base64url");
    return computed === codeChallenge;
}

function getServerUrl(): string {
    return (process.env.MCP_SERVER_URL || "").replace(/\/$/, "");
}

// ─── Login Page HTML ────────────────────────────────────────────────
const getLoginPageHtml = (params: { client_id: string, client_name: string, redirect_uri: string, state: string, code_challenge: string, code_challenge_method: string, scope: string, error_display: string, error_message: string }) => `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QBO MCP – Autorizar Acceso</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e0e0e0;
        }
        .card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 48px 40px;
            max-width: 420px;
            width: 90%;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
        }
        .logo { text-align: center; margin-bottom: 24px; font-size: 48px; }
        h1 { text-align: center; font-size: 22px; margin-bottom: 8px; color: #fff; }
        .subtitle { text-align: center; font-size: 14px; color: #aaa; margin-bottom: 32px; }
        .client-name { color: #a78bfa; font-weight: 600; }
        label { display: block; font-size: 13px; margin-bottom: 6px; color: #ccc; }
        input[type=password] {
            width: 100%; padding: 14px 16px; border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.08);
            color: #fff; font-size: 16px; outline: none; transition: border-color 0.2s;
        }
        input[type=password]:focus { border-color: #a78bfa; }
        .error { color: #f87171; font-size: 13px; margin-top: 8px; display: ${params.error_display}; }
        button {
            width: 100%; padding: 14px; border: none; border-radius: 12px;
            background: linear-gradient(135deg, #7c3aed 0%, #a78bfa 100%);
            color: #fff; font-size: 16px; font-weight: 600; cursor: pointer;
            margin-top: 24px; transition: transform 0.1s, box-shadow 0.2s;
        }
        button:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(124,58,237,0.4); }
        button:active { transform: translateY(0); }
        .footer { text-align: center; margin-top: 24px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">🔐</div>
        <h1>Autorizar Acceso</h1>
        <p class="subtitle">
            <span class="client-name">${params.client_name}</span> quiere conectarse a tu servidor QBO MCP.
        </p>
        <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="${params.client_id}">
            <input type="hidden" name="redirect_uri" value="${params.redirect_uri}">
            <input type="hidden" name="state" value="${params.state}">
            <input type="hidden" name="code_challenge" value="${params.code_challenge}">
            <input type="hidden" name="code_challenge_method" value="${params.code_challenge_method}">
            <input type="hidden" name="scope" value="${params.scope}">
            <label for="token">Token de Seguridad MCP</label>
            <input type="password" name="token" id="token" placeholder="Ingresa tu MCP_SECURITY_TOKEN" required autofocus>
            <p class="error">${params.error_message}</p>
            <button type="submit">🚀 Autorizar Acceso</button>
        </form>
        <p class="footer">QBO MCP Server &middot; Macom Engineering 🛡️</p>
    </div>
</body>
</html>
`;

export async function startOAuthServer(server: McpServer) {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(cors());

    const serverUrl = getServerUrl();
    const securityToken = process.env.MCP_SECURITY_TOKEN?.trim() || "";

    console.log(`OAuth2 Server URL: ${serverUrl}`);
    console.log(`OAuth2 Security Token configured: ${securityToken ? 'Yes' : 'No'}`);

    app.get("/", (req, res) => {
        const html = `
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>QBO MCP Server Status</title>
            <style>
                body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; line-height: 1.6; text-align: center; }
                .status { display: inline-block; padding: 8px 16px; border-radius: 20px; background: #10b981; font-weight: bold; margin-bottom: 20px; }
                h1 { color: #fff; font-size: 2.5rem; margin-bottom: 10px; }
                p { color: #94a3b8; font-size: 1.1rem; }
                .endpoint { font-family: monospace; background: #1e293b; padding: 12px 20px; border-radius: 8px; font-size: 1.2rem; color: #38bdf8; display: block; margin: 30px auto; width: fit-content; }
            </style>
        </head>
        <body>
            <div class="status">● ONLINE</div>
            <h1>QBO MCP Server</h1>
            <p>Servidor MCP activo y listo para conectar con Claude.</p>
            <span class="endpoint">${serverUrl}/mcp</span>
            <p style="font-size: 0.9rem;">Configurador OAuth2 disponible para Claude Web & Mobile.</p>
        </body>
        </html>
        `;
        res.send(html);
    });

    app.get("/.well-known/oauth-authorization-server", (req, res) => {
        res.json({
            issuer: serverUrl,
            authorization_endpoint: `${serverUrl}/authorize`,
            token_endpoint: `${serverUrl}/token`,
            registration_endpoint: `${serverUrl}/register`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            code_challenge_methods_supported: ["S256"],
            token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
            scopes_supported: ["mcp:tools"],
        });
    });

    app.get("/.well-known/openid-configuration", (req, res) => {
        res.json({
            issuer: serverUrl,
            authorization_endpoint: `${serverUrl}/authorize`,
            token_endpoint: `${serverUrl}/token`,
            registration_endpoint: `${serverUrl}/register`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            code_challenge_methods_supported: ["S256"],
        });
    });

    app.get("/.well-known/oauth-protected-resource", (req, res) => {
        res.json({
            resource: serverUrl,
            authorization_servers: [serverUrl],
            scopes_supported: ["mcp:tools"],
        });
    });

    app.post("/register", (req, res) => {
        const client_data = req.body || {};
        const client_id = generateToken(18);
        const client_secret = generateToken(24);

        oauth_clients[client_id] = {
            client_secret,
            client_name: client_data.client_name || "Claude",
            redirect_uris: client_data.redirect_uris || [],
            grant_types: client_data.grant_types || ["authorization_code"],
            token_endpoint_auth_method: client_data.token_endpoint_auth_method || "none",
        };

        console.log(`OAuth2 client registered: ${client_id} (${oauth_clients[client_id].client_name})`);

        res.status(201).json({
            client_id,
            client_secret,
            client_name: oauth_clients[client_id].client_name,
            redirect_uris: oauth_clients[client_id].redirect_uris,
            grant_types: oauth_clients[client_id].grant_types,
            token_endpoint_auth_method: oauth_clients[client_id].token_endpoint_auth_method,
        });
    });

    app.get("/authorize", (req, res) => {
        const client_id = (req.query.client_id as string) || "";
        const redirect_uri = (req.query.redirect_uri as string) || "";
        const state = (req.query.state as string) || "";
        const code_challenge = (req.query.code_challenge as string) || "";
        const code_challenge_method = (req.query.code_challenge_method as string) || "S256";
        const scope = (req.query.scope as string) || "mcp:tools";

        let client_name = "Claude";
        if (oauth_clients[client_id]) {
            client_name = oauth_clients[client_id].client_name;
        }

        res.send(getLoginPageHtml({
            client_id, client_name, redirect_uri, state, code_challenge, code_challenge_method, scope,
            error_display: "none", error_message: ""
        }));
    });

    app.post("/authorize", (req, res) => {
        const token = (req.body.token || "").trim();
        const client_id = req.body.client_id || "";
        const redirect_uri = req.body.redirect_uri || "";
        const state = req.body.state || "";
        const code_challenge = req.body.code_challenge || "";
        const code_challenge_method = req.body.code_challenge_method || "S256";
        const scope = req.body.scope || "mcp:tools";

        if (token !== securityToken) {
            console.warn(`OAuth2 authorization failed: invalid token from ${req.ip}`);
            let client_name = "Claude";
            if (oauth_clients[client_id]) {
                client_name = oauth_clients[client_id].client_name;
            }
            res.send(getLoginPageHtml({
                client_id, client_name, redirect_uri, state, code_challenge, code_challenge_method, scope,
                error_display: "block", error_message: "❌ Token inválido. Verifica tu MCP_SECURITY_TOKEN."
            }));
            return;
        }

        const auth_code = generateToken(24);
        auth_codes[auth_code] = {
            client_id, redirect_uri, code_challenge, code_challenge_method, scope,
            expires: Date.now() + 300000 // 5 minutes
        };

        console.log(`OAuth2 authorization granted for client ${client_id}`);

        let redirect_url = `${redirect_uri}?code=${encodeURIComponent(auth_code)}`;
        if (state) {
            redirect_url += `&state=${encodeURIComponent(state)}`;
        }
        res.redirect(302, redirect_url);
    });

    app.post("/token", (req, res) => {
        const grant_type = req.body.grant_type;
        
        if (grant_type === "authorization_code") {
            const code = req.body.code;
            const code_verifier = req.body.code_verifier;

            if (!auth_codes[code]) {
                console.warn("OAuth2 token request: invalid authorization code");
                return res.status(400).json({ error: "invalid_grant", error_description: "Invalid authorization code" });
            }

            const code_data = auth_codes[code];
            delete auth_codes[code];

            if (Date.now() > code_data.expires) {
                console.warn("OAuth2 token request: expired authorization code");
                return res.status(400).json({ error: "invalid_grant", error_description: "Authorization code expired" });
            }

            const req_client_id = req.body.client_id;
            if (req_client_id && req_client_id !== code_data.client_id) {
                console.warn(`OAuth2 token request: client_id mismatch (${req_client_id} vs ${code_data.client_id})`);
                return res.status(400).json({ error: "invalid_client", error_description: "client_id mismatch" });
            }

            if (code_data.code_challenge && code_verifier) {
                if (!verifyPkce(code_verifier, code_data.code_challenge)) {
                    console.warn("OAuth2 token request: PKCE verification failed");
                    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
                }
            }

            const new_access_token = generateToken();
            const new_refresh_token = generateToken();
            const expires_in = 3600;

            access_tokens[new_access_token] = {
                client_id: code_data.client_id,
                scope: code_data.scope,
                expires: Date.now() + (expires_in * 1000)
            };

            refresh_tokens[new_refresh_token] = {
                client_id: code_data.client_id,
                scope: code_data.scope,
                access_token: new_access_token
            };

            console.log(`OAuth2 access token issued for client ${code_data.client_id}`);

            return res.json({
                access_token: new_access_token,
                token_type: "Bearer",
                expires_in,
                refresh_token: new_refresh_token,
                scope: code_data.scope
            });
        } else if (grant_type === "refresh_token") {
            const rt = req.body.refresh_token;

            if (!refresh_tokens[rt]) {
                return res.status(400).json({ error: "invalid_grant", error_description: "Invalid refresh token" });
            }

            const rt_data = refresh_tokens[rt];
            delete refresh_tokens[rt];

            const req_client_id = req.body.client_id;
            if (req_client_id && req_client_id !== rt_data.client_id) {
                console.warn(`OAuth2 refresh request: client_id mismatch (${req_client_id} vs ${rt_data.client_id})`);
                return res.status(400).json({ error: "invalid_client", error_description: "client_id mismatch" });
            }

            const old_at = rt_data.access_token;
            if (access_tokens[old_at]) {
                delete access_tokens[old_at];
            }

            const new_access_token = generateToken();
            const new_refresh_token = generateToken();
            const expires_in = 3600;

            access_tokens[new_access_token] = {
                client_id: rt_data.client_id,
                scope: rt_data.scope,
                expires: Date.now() + (expires_in * 1000)
            };

            refresh_tokens[new_refresh_token] = {
                client_id: rt_data.client_id,
                scope: rt_data.scope,
                access_token: new_access_token
            };

            console.log(`OAuth2 token refreshed for client ${rt_data.client_id}`);

            return res.json({
                access_token: new_access_token,
                token_type: "Bearer",
                expires_in,
                refresh_token: new_refresh_token,
                scope: rt_data.scope
            });
        }

        return res.status(400).json({ error: "unsupported_grant_type" });
    });

    // ─── MCP Endpoints Authentication ──────────────────────────────────
    app.use("/mcp", (req, res, next) => {
        if (!securityToken) {
            return next();
        }

        const authHeader = req.headers.authorization || "";
        let isValid = false;

        if (authHeader.startsWith("Bearer ")) {
            const bearerToken = authHeader.substring(7).trim();
            if (bearerToken === securityToken) {
                isValid = true;
            } else if (access_tokens[bearerToken]) {
                const token_data = access_tokens[bearerToken];
                if (Date.now() < token_data.expires) {
                    isValid = true;
                } else {
                    delete access_tokens[bearerToken];
                    console.log("OAuth2 access token expired, removed");
                }
            }
        }

        if (!isValid) {
            const queryToken = req.query.token as string || "";
            if (queryToken === securityToken) {
                isValid = true;
            }
        }

        if (!isValid) {
            console.warn(`UNAUTHORIZED: ${req.path} from ${req.ip}.`);
            return res.status(401).json({ error: "Unauthorized. Please authenticate via OAuth2 or Bearer token." });
        }

        next();
    });

    // ─── SSEServerTransport ────────────────────────────────────────────
    const sseTransports = new Map<string, SSEServerTransport>();

    app.get("/mcp/sse", async (req, res) => {
        const transport = new SSEServerTransport("/mcp/messages", res);
        await server.connect(transport);
        
        const sessionId = transport.sessionId;
        sseTransports.set(sessionId, transport);
        
        res.on("close", () => {
            sseTransports.delete(sessionId);
        });
    });

    app.post("/mcp/messages", async (req, res) => {
        const sessionId = req.query.sessionId as string;
        const transport = sseTransports.get(sessionId);
        
        if (!transport) {
            return res.status(404).send("Session not found");
        }
        
        await transport.handlePostMessage(req, res);
    });

    const port = process.env.PORT ? parseInt(process.env.PORT) : 8000;
    const host = process.env.HOST || "0.0.0.0";
    
    app.listen(port, host, () => {
        console.log(`QBO MCP Server listening on ${host}:${port} via Express (SSE + OAuth2)`);
    });
}
