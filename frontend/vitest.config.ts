import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

/**
 * Test config kept separate from vite.config.ts so the dev-server proxy rules -
 * which point at two live services - are not loaded by the test runner.
 *
 * `environment: "jsdom"` only for the tests that render a component; the pure
 * modules under lib/ do not need it, but a single environment is cheaper than
 * per-file annotations at this size.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: false,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    restoreMocks: true,
  },
});
