/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AZURE_CLIENT_ID?: string;
  readonly VITE_AZURE_TENANT_ID?: string;
  readonly VITE_AZURE_REDIRECT_URI?: string;
  readonly VITE_AUTH_BYPASS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
