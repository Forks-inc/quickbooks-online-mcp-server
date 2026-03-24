# QuickBooks Online MCP Server

Implementación premium del protocolo MCP para conectar QuickBooks Online con Claude. Soporta tanto uso local (stdio) como remoto (SSE con OAuth2).

## 🚀 Inicio Rápido con Claude (Remoto / SSE)

Este servidor está diseñado para funcionar como un "Custom Connector" en Claude. 

### 1. Requisitos
- Una cuenta en [Intuit Developer](https://developer.intuit.com/).
- Una App de QuickBooks con `Client ID` y `Client Secret`.
- En el portal de Intuit, añade la URL de redirección: `https://tu-servidor.com/auth/qbo/callback`

### 2. Configuración (.env)
Crea un archivo `.env` basado en `.env.example`:
```env
QUICKBOOKS_CLIENT_ID=...
QUICKBOOKS_CLIENT_SECRET=...
QUICKBOOKS_ENVIRONMENT=production
MCP_SERVER_URL=https://tu-servidor.com
MCP_TRANSPORT=sse
MCP_SECURITY_TOKEN=una-clave-larga-y-segura
```

### 3. Autenticación Transparente
1. Agrega el servidor en Claude usando la URL `https://tu-servidor.com/mcp/sse`.
2. Claude te pedirá hacer **"Log in"**.
3. Al hacer clic, serás redirigido automáticamente a la página oficial de **QuickBooks**.
4. Autoriza el acceso y ¡listo! El servidor guardará los tokens automáticamente y Claude tendrá acceso a tus herramientas.

---

## 💻 Uso Local (Desktop)

Si prefieres usarlo localmente en Claude Desktop:

1. Instala dependencias: `npm install`
2. Configura tu `.env` con `MCP_TRANSPORT=stdio`.
3. Ejecuta `pnpm run auth` para generar los tokens iniciales.
4. Agrega la configuración a tu `claude_desktop_config.json`.

---

## 🛠️ Herramientas Disponibles

El servidor expone herramientas completas (Crear, Leer, Buscar, Actualizar, Borrar) para:

- **Clientes (Customers)**
- **Estimaciones (Estimates)**
- **Facturas (Invoices)**
- **Gastos (Purchases)**
- **Proveedores (Vendors)**
- **Cuentas (Accounts)**
- **Asientos Contables (Journal Entries)**
- **Pagos de Facturas (Bill Payments)**
- **Productos/Servicios (Items)**
- **Empleados (Employees)**

---

## 🛡️ Seguridad
El servidor utiliza **OAuth2 con PKCE** y soporte para **Dynamic Client Registration**, lo que lo hace compatible con todas las versiones de Claude (Web, iOS, Android y Desktop).

Desarrollado por **Macom Engineering** 🛡️
