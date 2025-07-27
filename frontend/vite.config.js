import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8080",
      },
      "/oauth2": {
        // OAuth2 로그인 경로도 백엔드로 프록시
        target: "http://localhost:8080",
        // changeOrigin: true,
      },
      "/login/oauth2": {
        // OAuth2 콜백 경로도 백엔드로 프록시
        target: "http://localhost:8080",
        // changeOrigin: true,
      },
    },
  },
});
