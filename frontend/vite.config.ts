import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Two services behind one origin. Vite matches proxy keys in insertion
    // order and takes the first prefix that matches, so the analyst rule is
    // declared before the general `/api` one - otherwise every analyst call
    // would be handed to the backend on :8000, which does not serve those
    // routes, and the panel would report the layer as unavailable while it was
    // running perfectly well on :8100.
    proxy: {
      "/api/v1/analyst": {
        target: "http://127.0.0.1:8100",
        changeOrigin: true,
      },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
