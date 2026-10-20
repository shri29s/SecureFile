import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({
  root: 'ui', plugins: [react(), tailwindcss()],
  server: { proxy: Object.fromEntries(['/users', '/groups', '/me', '/admin', '/public', '/ipfs', '/health'].map(p => [p, 'http://127.0.0.1:3001'])) },
  build: { outDir: 'dist', emptyOutDir: true, rollupOptions: { output: { manualChunks: { ethereum: ['ethers'], react: ['react', 'react-dom'] } } } }
});
