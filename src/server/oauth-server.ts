import express from "express";
import cors from "cors";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import OAuthClient from 'intuit-oauth';
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// ─── In-Memory OAuth2 Storage ───────────────────────────────────────
const oauth_clients: Record<string, { client_secret: string, client_name: string, redirect_uris: string[], grant_types: string[], token_endpoint_auth_method: string }> = {};
const auth_codes: Record<string, { client_id: string, redirect_uri: string, code_challenge: string, code_challenge_method: string, scope: string, expires: number }> = {};
const access_tokens: Record<string, { client_id: string, scope: string, expires: number }> = {};
const refresh_tokens: Record<string, { client_id: string, scope: string, access_token: string }> = {};

// Temporary storage to bridge Claude request and QBO callback
const pending_claude_auths: Record<string, { client_id: string, redirect_uri: string, scope: string, state: string, code_challenge: string, code_challenge_method: string }> = {};

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

function isQboConnected(): boolean {
    return !!(process.env.QUICKBOOKS_REFRESH_TOKEN && process.env.QUICKBOOKS_REALM_ID);
}

export async function startOAuthServer(server: McpServer) {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(cors());

    const serverUrl = getServerUrl();

    const qboOauthClient = new OAuthClient({
        clientId: process.env.QUICKBOOKS_CLIENT_ID || '',
        clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET || '',
        environment: process.env.QUICKBOOKS_ENVIRONMENT as any || 'sandbox',
        redirectUri: `${serverUrl}/auth/qbo/callback`,
    });

    console.log(`Seamless OAuth2 Server enabled at: ${serverUrl}`);

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
                .qbo-status { margin-top: 20px; padding: 15px; border-radius: 8px; background: rgba(255,255,255,0.05); }
            </style>
        </head>
        <body>
            <div class="status">● ONLINE</div>
            <h1>QBO MCP Server</h1>
            <p>Servidor MCP configurado para QuickBooks.</p>
            <span class="endpoint">${serverUrl}/mcp</span>
            <div class="qbo-status">
                Estado QBO: ${isQboConnected() ? '<b style="color:#10b981;">Enlazado ✅</b>' : '<b style="color:#f59e0b;">Pendiente ⚠️</b>'}
            </div>
        </body>
        </html>
        `;
        res.send(html);
    });

    // ─── QBO OAuth Callback ───────────────────────────────────────────
    app.get("/auth/qbo/callback", async (req, res) => {
        try {
            const bridgeId = req.query.state as string;
            const claudeParams = pending_claude_auths[bridgeId];
            delete pending_claude_auths[bridgeId];

            const authResponse: any = await qboOauthClient.createToken(req.url);
            const token = authResponse.json || authResponse.token;
            const realmId = req.query.realmId;

            console.log("✅ QuickBooks connection established!");

            // Persist tokens
            process.env.QUICKBOOKS_REFRESH_TOKEN = token.refresh_token;
            process.env.QUICKBOOKS_REALM_ID = realmId as string;

            const envPath = path.resolve(process.cwd(), '.env');
            if (fs.existsSync(envPath)) {
                let envContent = fs.readFileSync(envPath, 'utf8');
                envContent = envContent.replace(/QUICKBOOKS_REFRESH_TOKEN=.*/g, `QUICKBOOKS_REFRESH_TOKEN=${token.refresh_token}`);
                if (realmId) {
                    envContent = envContent.replace(/QUICKBOOKS_REALM_ID=.*/g, `QUICKBOOKS_REALM_ID=${realmId}`);
                }
                fs.writeFileSync(envPath, envContent);
            }

            if (!claudeParams) {
                return res.redirect('/');
            }

            // Successfully got QBO tokens, now respond to Claude's original request
            const auth_code = generateToken(24);
            auth_codes[auth_code] = {
                client_id: claudeParams.client_id,
                redirect_uri: claudeParams.redirect_uri,
                code_challenge: claudeParams.code_challenge,
                code_challenge_method: claudeParams.code_challenge_method,
                scope: claudeParams.scope,
                expires: Date.now() + 300000
            };

            let redirect_url = `${claudeParams.redirect_uri}?code=${encodeURIComponent(auth_code)}`;
            if (claudeParams.state) {
                redirect_url += `&state=${encodeURIComponent(claudeParams.state)}`;
            }
            
            console.log(`Redirecting back to Claude with auth_code...`);
            res.redirect(302, redirect_url);

        } catch (e: any) {
            console.error('QBO Auth Error:', e);
            res.status(500).send('Error linking with QuickBooks.');
        }
    });

    // ─── Standard OAuth2 Metadata ─────────────────────────────────────
    const wellKnownAuth = (req: any, res: any) => {
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
    };

    const wellKnownOpenId = (req: any, res: any) => {
        res.json({
            issuer: serverUrl,
            authorization_endpoint: `${serverUrl}/authorize`,
            token_endpoint: `${serverUrl}/token`,
            registration_endpoint: `${serverUrl}/register`,
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            code_challenge_methods_supported: ["S256"],
        });
    };

    app.get("/.well-known/oauth-authorization-server", wellKnownAuth);
    app.get("/mcp/sse/.well-known/oauth-authorization-server", wellKnownAuth);
    
    app.get("/.well-known/openid-configuration", wellKnownOpenId);
    app.get("/mcp/sse/.well-known/openid-configuration", wellKnownOpenId);

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

        res.status(201).json({ client_id, client_secret });
    });

    // ─── MAIN AUTHORIZE ENDPOINT (Claude hits this) ──────────────────
    app.get("/authorize", (req, res) => {
        const bridgeId = generateToken(12);
        
        // Save Claude's parameters to resume after QBO callback
        pending_claude_auths[bridgeId] = {
            client_id: (req.query.client_id as string) || "",
            redirect_uri: (req.query.redirect_uri as string) || "",
            state: (req.query.state as string) || "",
            code_challenge: (req.query.code_challenge as string) || "",
            code_challenge_method: (req.query.code_challenge_method as string) || "S256",
            scope: (req.query.scope as string) || "mcp:tools"
        };

        // Redirect immediately to QuickBooks authorize
        const authUri = qboOauthClient.authorizeUri({
            scope: [OAuthClient.scopes.Accounting],
            state: bridgeId,
        });

        console.log(`Claude connection started. Redirecting user to QuickBooks...`);
        res.redirect(authUri as any);
    });

    // ─── Token Exchange ───────────────────────────────────────────────
    app.post("/token", (req, res) => {
        const grant_type = req.body.grant_type;
        
        if (grant_type === "authorization_code") {
            const code = req.body.code;
            const code_verifier = req.body.code_verifier;

            if (!auth_codes[code]) return res.status(400).json({ error: "invalid_grant" });

            const code_data = auth_codes[code];
            delete auth_codes[code];

            if (Date.now() > code_data.expires) return res.status(400).json({ error: "invalid_grant", error_description: "Expired" });

            if (code_data.code_challenge && code_verifier) {
                if (!verifyPkce(code_verifier, code_data.code_challenge)) return res.status(400).json({ error: "invalid_grant" });
            }

            const new_access_token = generateToken();
            const new_refresh_token = generateToken();
            const expires_in = 3600;

            access_tokens[new_access_token] = { client_id: code_data.client_id, scope: code_data.scope, expires: Date.now() + (expires_in * 1000) };
            refresh_tokens[new_refresh_token] = { client_id: code_data.client_id, scope: code_data.scope, access_token: new_access_token };

            return res.json({
                access_token: new_access_token,
                token_type: "Bearer",
                expires_in,
                refresh_token: new_refresh_token,
                scope: code_data.scope
            });
        } else if (grant_type === "refresh_token") {
            const rt = req.body.refresh_token;
            if (!refresh_tokens[rt]) return res.status(400).json({ error: "invalid_grant" });

            const rt_data = refresh_tokens[rt];
            delete refresh_tokens[rt];
            if (access_tokens[rt_data.access_token]) delete access_tokens[rt_data.access_token];

            const new_access_token = generateToken();
            const new_refresh_token = generateToken();
            const expires_in = 3600;

            access_tokens[new_access_token] = { client_id: rt_data.client_id, scope: rt_data.scope, expires: Date.now() + (expires_in * 1000) };
            refresh_tokens[new_refresh_token] = { client_id: rt_data.client_id, scope: rt_data.scope, access_token: new_access_token };

            return res.json({ access_token: new_access_token, token_type: "Bearer", expires_in, refresh_token: new_refresh_token });
        }
        return res.status(400).json({ error: "unsupported_grant_type" });
    });

    // ─── Middleware de Seguridad ──────────────────────────────────────
    app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
        next();
    });

    app.use("/mcp", (req, res, next) => {
        // Allow OAuth2 discovery endpoints to be accessed without authentication
        if (req.path.includes(".well-known")) {
            return next();
        }

        // Allow SSE connection establishment without authentication. 
        // Actual MCP commands are sent via POST /mcp/messages which will be authenticated.
        if (req.path === "/sse" && req.method === "GET") {
            return next();
        }

        const authHeader = req.headers.authorization || "";
        let isValid = false;

        const securityToken = process.env.MCP_SECURITY_TOKEN?.trim();

        if (authHeader.startsWith("Bearer ")) {
            const bearerToken = authHeader.substring(7).trim();
            if (securityToken && bearerToken === securityToken) {
                isValid = true;
            } else if (access_tokens[bearerToken]) {
                const token_data = access_tokens[bearerToken];
                if (Date.now() < token_data.expires) isValid = true;
                else delete access_tokens[bearerToken];
            }
        }

        if (!isValid) {
            const queryToken = req.query.token as string || "";
            if (securityToken && queryToken === securityToken) isValid = true;
        }

        if (!isValid) {
            console.log("❌ Unauthorized attempt to MCP endpoint:", req.url);
            res.setHeader("WWW-Authenticate", 'Bearer realm="mcp"');
            return res.status(401).json({ error: "Unauthorized" });
        }
        next();
    });

    // ─── SSEServerTransport ────────────────────────────────────────────
    const sseTransports = new Map<string, SSEServerTransport>();

    app.get("/mcp/sse", async (req, res) => {
        console.log("📡 New SSE Connection request");
        // Disable buffering for proxies (Nginx/Traefik)
        res.setHeader('X-Accel-Buffering', 'no');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        const transport = new SSEServerTransport("/mcp/messages", res);
        await server.connect(transport);
        sseTransports.set(transport.sessionId, transport);
        
        console.log(`✅ SSE Session started: ${transport.sessionId}`);
        
        res.on("close", () => {
            console.log(`🔌 SSE Session closed: ${transport.sessionId}`);
            sseTransports.delete(transport.sessionId);
        });
    });

    app.post("/mcp/messages", async (req, res) => {
        const sessionId = req.query.sessionId as string;
        const transport = sseTransports.get(sessionId);
        
        if (!transport) {
            console.log(`❌ Message session not found: ${sessionId}`);
            return res.status(404).send("Session not found");
        }
        
        await transport.handlePostMessage(req, res);
    });

    const port = process.env.PORT ? parseInt(process.env.PORT) : 8000;
    const host = process.env.HOST || "0.0.0.0";
    app.listen(port, host, () => {
        console.log("--------------------------------------------------");
        console.log(`🚀 QBO MCP Server running on ${host}:${port}`);
        console.log(`🔗 Transport: SSE | Base URL: ${serverUrl}`);
        console.log("--------------------------------------------------");
    });
}
