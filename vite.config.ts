import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "src",
  plugins: [react()],
  build: {
    outDir: "../dist",
    assetsDir: "assets",
  },
  server: {
    port: 5173,
  },
});
