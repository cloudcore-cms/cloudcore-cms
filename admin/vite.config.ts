import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8787',
        changeOrigin: true,
        configure: (proxy) => {
          // Preserve X-CloudCore-Request header through the proxy
          proxy.on('proxyReq', (proxyReq, req) => {
            // Copy the CSRF header if present
            const csrfHeader = req.headers['x-cloudcore-request'];
            if (csrfHeader) {
              proxyReq.setHeader('X-CloudCore-Request', csrfHeader);
            }
          });
        },
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
