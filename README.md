# QuickBooks Online MCP Server

This is a Model Context Protocol (MCP) server implementation for QuickBooks Online integration.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following variables:
```env
QUICKBOOKS_CLIENT_ID=your_client_id
QUICKBOOKS_CLIENT_SECRET=your_client_secret
QUICKBOOKS_ENVIRONMENT=sandbox
```

3. Get your Client ID and Client Secret:
   - Go to the [Intuit Developer Portal](https://developer.intuit.com/)
   - Create a new app or select an existing one
   - Get the Client ID and Client Secret from the app's keys section
   - Add `http://localhost:8000/callback` to the app's Redirect URIs

## Authentication

There are two ways to authenticate with QuickBooks Online:

### Option 1: Using Environment Variables

If you already have a refresh token and realm ID, you can add them directly to your `.env` file:

```env
QUICKBOOKS_REFRESH_TOKEN=your_refresh_token
QUICKBOOKS_REALM_ID=your_realm_id
```

### Option 2: Using the OAuth Flow

If you don't have a refresh token, you can use the built-in OAuth flow:

This will:
- Start a temporary local server
- Open your default browser automatically
- Redirect you to QuickBooks for authentication
- Save the tokens to your `.env` file once authenticated
- Close automatically when complete

## Running the Server with MCP OAuth2 for Custom Connectors

The server now supports acting as an OAuth2 authorization server for Claude's Custom Connectors. This allows Claude (Web, iOS, Android, Desktop) to securely authenticate with your server using an OAuth2 flow.

To enable this:

1. Add your desired security token in `.env`:
   \`\`\`env
   MCP_SECURITY_TOKEN=your_secure_random_token_here
   MCP_SERVER_URL=https://your-public-url.com
   \`\`\`

2. Run the server with SSE transport:
   \`\`\`bash
   MCP_TRANSPORT=sse npm run start
   \`\`\`
   
The server will start an Express application with OAuth2 discovery endpoints, dynamic registration, authorization flow, and the SSE transport at `/mcp/sse`.

## Usage

After authentication is set up, you can use the MCP server to interact with QuickBooks Online. The server provides various tools for managing customers, estimates, bills, and more.

## Available Tools

Added tools for Create, Delete, Get, Search, Update for the following entities:


- Account
- Bill Payment
- Bill
- Customer
- Employee
- Estimate
- Invoice
- Item
- Journal Entry
- Purchase
- Vendor


## Error Handling

If you see an error message like "QuickBooks not connected", make sure to:

1. Check that your `.env` file contains all required variables
2. Verify that your tokens are valid and not expired

