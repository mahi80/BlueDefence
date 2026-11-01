/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Type errors fail the build (tsc gate); ESLint is a dev-time script, not a build blocker,
  // to keep CI deterministic across eslint 9 / flat-config churn.
  eslint: { ignoreDuringBuilds: true },
  // Every backend call goes through a console route handler (session checked, key added server-side);
  // there is deliberately no pass-through rewrite to the backend: the browser never talks to it directly.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        ],
      },
    ];
  },
};
export default nextConfig;
