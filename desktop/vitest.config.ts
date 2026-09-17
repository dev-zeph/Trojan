import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Separate from vite.config.ts because that file reads TAURI_DEV_HOST and
// carries a fixed dev-server port meant for `tauri dev` -- neither applies
// to running unit tests.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
