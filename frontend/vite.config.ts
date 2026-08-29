import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend talks to FastAPI directly - REST for history, WebSocket for the
// live feed. The dev proxy exists only so both run on one origin during
// development; it is not a Node tier in front of the API, which the design spec
// explicitly rules out ("inserting a Node proxy in front of a Python API adds a
// network hop and latency to the one path where latency is graded").
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
