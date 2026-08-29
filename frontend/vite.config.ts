import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Section 8.1: React talks to FastAPI directly, no Node proxy in the request
// path. The dev server just proxies /ws and /api to the mock server (or the
// real backend later) so the browser can use relative URLs.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/ws": { target: "ws://localhost:8787", ws: true },
      "/api": { target: "http://localhost:8787", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
});