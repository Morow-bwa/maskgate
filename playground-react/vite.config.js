import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/playground/",
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/playground/api": "http://127.0.0.1:8080",
      "/playground/config": "http://127.0.0.1:8080",
    },
  },
});
