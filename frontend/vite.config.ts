import react from '@vitejs/plugin-react';
import { loadEnv } from 'vite';
import { defineConfig } from 'vitest/config';

// The browser only ever talks to its own origin. In development Vite forwards /api/* to the backend with the
// prefix removed, exactly like the nginx container does in Docker, so the backend needs no CORS configuration.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const target = env.DEV_API_TARGET || 'http://127.0.0.1:8000';
  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': { target, changeOrigin: false, rewrite: (path) => path.replace(/^\/api/, '') },
      },
    },
    preview: { host: '127.0.0.1', port: 4173 },
    build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 600 },
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      include: ['src/**/*.test.{ts,tsx}'],
      css: false,
      restoreMocks: true,
    },
  };
});
