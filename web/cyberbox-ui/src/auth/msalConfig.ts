import { Configuration, LogLevel } from '@azure/msal-browser';

/**
 * Azure AD / Entra ID — MSAL configuration.
 *
 * To set up:
 *   1. Go to Azure Portal → Entra ID → App registrations → New registration
 *   2. Name: "CyberboxSIEM"
 *   3. Redirect URI (SPA): http://localhost:5173 (dev), https://cyberbox.yourdomain.com (prod)
 *   4. Under "API permissions", add: User.Read (delegated)
 *   5. Under "App roles", create: admin, analyst, viewer, ingestor
 *   6. Under "Token configuration", add optional claims: email, preferred_username
 *   7. Copy the Application (client) ID and Directory (tenant) ID below
 */

// ── Replace these with your Azure AD App Registration values ────────────────

const CLIENT_ID = import.meta.env.VITE_AZURE_CLIENT_ID || 'YOUR_CLIENT_ID';
const TENANT_ID = import.meta.env.VITE_AZURE_TENANT_ID || 'YOUR_TENANT_ID';
const REDIRECT_URI = import.meta.env.VITE_AZURE_REDIRECT_URI || window.location.origin;

// ── MSAL configuration ─────────────────────────────────────────────────────

export const msalConfig: Configuration = {
  auth: {
    clientId: CLIENT_ID,
    authority: `https://login.microsoftonline.com/${TENANT_ID}`,
    redirectUri: REDIRECT_URI,
    postLogoutRedirectUri: REDIRECT_URI,
  },
  cache: {
    cacheLocation: 'localStorage',
  },
  system: {
    loggerOptions: {
      logLevel: LogLevel.Warning,
      piiLoggingEnabled: false,
    },
  },
};

/**
 * Scopes requested during login.
 * - `openid` + `profile` + `email` are standard OIDC scopes
 * - `api://<CLIENT_ID>/access` is the custom scope for your API
 *   (configure under "Expose an API" in the App Registration)
 */
export const loginScopes = {
  scopes: ['openid', 'profile', 'email'],
};

/**
 * Scopes for acquiring tokens to call the CyberboxSIEM API.
 * After setting up "Expose an API", replace with your actual scope URI.
 */
export const apiScopes = {
  scopes: [`api://${CLIENT_ID}/access`],
};
