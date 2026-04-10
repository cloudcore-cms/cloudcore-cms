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
                configure: function (proxy) {
                    // Preserve X-CloudCore-Request header through the proxy
                    proxy.on('proxyReq', function (proxyReq, req) {
                        // Copy the CSRF header if present
                        var csrfHeader = req.headers['x-cloudcore-request'];
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
