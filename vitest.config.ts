import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { 'cloudflare:workers': new URL('./test/cloudflare.ts', import.meta.url).pathname },
  },
  test: {
    environment: 'node',
    server: { deps: { inline: ['@cloudflare/workers-oauth-provider'] } },
  },
});
