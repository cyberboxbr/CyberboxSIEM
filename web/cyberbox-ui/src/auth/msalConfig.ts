import type { Configuration } from '@azure/msal-browser';

function readEnv(name: string): string {
  const value = import.meta.env[name as keyof ImportMetaEnv];
  return typeof value === 'string' ? value.trim() : '';
}

function isPlaceholder(value: string, placeholder: string): boolean {
  return !value || value === placeholder;
}

const CLIENT_ID = readEnv('VITE_AZURE_CLIENT_ID');
const TENANT_ID = readEnv('VITE_AZURE_TENANT_ID');
const REDIRECT_URI = readEnv('VITE_AZURE_REDIRECT_URI') || window.location.origin;
const AUTH_BYPASS = readEnv('VITE_AUTH_BYPASS').toLowerCase() === 'true';

export const isMicrosoftAuthConfigured =
  !isPlaceholder(CLIENT_ID, 'YOUR_CLIENT_ID') &&
  !isPlaceholder(TENANT_ID, 'YOUR_TENANT_ID');

export const isAuthBypassEnabled =
  AUTH_BYPASS || (import.meta.env.DEV && !isMicrosoftAuthConfigured);

export function getMsalConfig(): Configuration {
  return {
    auth: {
      clientId: CLIENT_ID,
      authority: `https://login.microsoftonline.com/${TENANT_ID}`,
      redirectUri: REDIRECT_URI,
      postLogoutRedirectUri: REDIRECT_URI,
    },
    cache: {
      cacheLocation: 'sessionStorage',
    },
  };
}

export const loginScopes = {
  scopes: ['openid', 'profile', 'email'],
};

export const apiScopes = {
  scopes: isMicrosoftAuthConfigured ? [`api://${CLIENT_ID}/access`] : [],
};
