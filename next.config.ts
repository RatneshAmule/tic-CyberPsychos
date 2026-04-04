import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // Allow large file uploads (forensic evidence can be multi-GB)
  experimental: {
    serverActions: {
      bodySizeLimit: '20gb',
    },
  },
  // ─── PERMANENT FIX ─────────────────────────────────────────────────────────
  // ZERO native modules. No serverExternalPackages needed.
  // All forensic analysis uses CLI tools (sqlite3, exiftool, identify, etc.)
  // via a separate worker process (scripts/analyze-worker.mjs).
  // Turbopack will NEVER encounter a native .node module.
  // ───────────────────────────────────────────────────────────────────────────
};

export default nextConfig;
