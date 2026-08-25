/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.PROOF_SERVER_URL ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
      "/auth": {
        target: process.env.PROOF_SERVER_URL ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
      "/preview": {
        target: process.env.PROOF_SERVER_URL ?? "http://127.0.0.1:8080",
        changeOrigin: false,
      },
    },
  },
});
