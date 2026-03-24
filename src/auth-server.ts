import OAuthClient from 'intuit-oauth';
import express from 'express';
import open from 'open';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const oauthClient = new OAuthClient({
  clientId: process.env.QUICKBOOKS_CLIENT_ID || '',
  clientSecret: process.env.QUICKBOOKS_CLIENT_SECRET || '',
  environment: process.env.QUICKBOOKS_ENVIRONMENT || 'sandbox',
  redirectUri: process.env.QUICKBOOKS_REDIRECTURI || 'http://localhost:8000/callback',
});

const app = express();

app.get('/', (req, res) => {
  if (!process.env.QUICKBOOKS_CLIENT_ID || !process.env.QUICKBOOKS_CLIENT_SECRET) {
      return res.status(400).send("❌ Please set QUICKBOOKS_CLIENT_ID and QUICKBOOKS_CLIENT_SECRET in your .env file before logging in.");
  }
  const authUri = oauthClient.authorizeUri({
    scope: [OAuthClient.scopes.Accounting],
    state: 'intuit-test',
  });
  console.log('Redirecting to QuickBooks for authorization...');
  res.redirect(authUri as any);
});

app.get('/callback', async (req, res) => {
  try {
    const authResponse: any = await oauthClient.createToken(req.url);
    const token = authResponse.json || authResponse.token;
    console.log('✅ Tokens acquired successfully!');
    
    const envPath = path.resolve(process.cwd(), '.env');
    let envContent = '';
    if (fs.existsSync(envPath)) {
        envContent = fs.readFileSync(envPath, 'utf8');
    }
    
    // Update or append refresh token
    if (envContent.includes('QUICKBOOKS_REFRESH_TOKEN=')) {
        envContent = envContent.replace(/QUICKBOOKS_REFRESH_TOKEN=.*/g, `QUICKBOOKS_REFRESH_TOKEN=${token.refresh_token}`);
    } else {
        envContent += `\nQUICKBOOKS_REFRESH_TOKEN=${token.refresh_token}`;
    }
    
    // Update or append realm ID
    const realmId = req.query.realmId;
    if (realmId) {
        if (envContent.includes('QUICKBOOKS_REALM_ID=')) {
            envContent = envContent.replace(/QUICKBOOKS_REALM_ID=.*/g, `QUICKBOOKS_REALM_ID=${realmId}`);
        } else {
            envContent += `\nQUICKBOOKS_REALM_ID=${realmId}`;
        }
    }

    fs.writeFileSync(envPath, envContent);
    res.send(`
        <div style="font-family: sans-serif; text-align: center; margin-top: 50px;">
            <h1 style="color: green;">✅ Conexión Exitosa con QuickBooks</h1>
            <p>Se ha guardado el <b>Refresh Token</b> y el <b>Realm ID</b> en tu archivo <code>.env</code>.</p>
            <p>Ya puedes cerrar esta ventana, detener este servidor en la terminal y proceder a subir tu proyecto a Dokploy.</p>
        </div>
    `);
    console.log('✅ Tokens guardados en el archivo .env.');
    console.log('✅ Puedes detener este proceso (Ctrl+C).');
    
    // Graceful shutdown after 3 seconds
    setTimeout(() => {
        process.exit(0);
    }, 3000);

  } catch (e: any) {
    console.error('❌ Failed to acquire token:', e.originalMessage || e.message || e);
    res.status(500).send('Failed to acquire token from QuickBooks.');
  }
});

const server = app.listen(8000, () => {
  console.log('--------------------------------------------------');
  console.log('🚀 Servidor de Autenticación de QuickBooks iniciado!');
  console.log('Abriendo el navegador en http://localhost:8000/');
  console.log('--------------------------------------------------');
  open('http://localhost:8000/');
});
