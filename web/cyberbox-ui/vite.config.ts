import { fileURLToPath, URL } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return;

          const inPackage = (name: string) =>
            id.includes(`/node_modules/${name}/`) || id.includes(`\\node_modules\\${name}\\`);

          if (
            inPackage('react') ||
            inPackage('react-dom') ||
            inPackage('react-router') ||
            inPackage('react-router-dom') ||
            inPackage('scheduler') ||
            inPackage('react-is')
          ) {
            return 'react-vendor';
          }

          if (
            inPackage('lucide-react') ||
            inPackage('@radix-ui/react-slot') ||
            inPackage('class-variance-authority') ||
            inPackage('clsx') ||
            inPackage('tailwind-merge')
          ) {
            return 'ui-vendor';
          }
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/healthz': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/metrics': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    restoreMocks: true,
    include: ['src/**/*.test.{ts,tsx}'],
    exclude: ['e2e/**', 'test-results/**', 'playwright-report/**'],
  },
});
