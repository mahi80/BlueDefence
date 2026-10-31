/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Type errors fail the build (tsc gate); ESLint is a dev-time script, not a build blocker,
  // to keep CI deterministic across eslint 9 / flat-config churn.
  eslint: { ignoreDuringBuilds: true },
  // The console is a read/write client of the existing ACP dashboard FastAPI backend.
  // Same-origin `/api/*` calls are proxied to it so the browser needs no CORS and no
  // API key in client code (the proxy host injects auth). Set AEGIS_API_ORIGIN at deploy.
  async rewrites() {
    const origin = process.env.AEGIS_API_ORIGIN || "";
    if (!origin) return [];
    return [{ source: "/api/:path*", destination: `${origin}/api/:path*` }];
  },
};
export default nextConfig;
