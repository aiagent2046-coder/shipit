/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
      {
        // Baseline security headers on every frontend response. DENY is safe:
        // the frontend is never embedded in an iframe. No CSP here — a correct
        // Next.js CSP needs a nonce-based script policy (Next injects inline
        // runtime scripts) and is deferred as a dedicated follow-up.
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains",
          },
        ],
      },
      {
        // The audit results page carries the per-audit access token in the
        // URL (?token=...). no-referrer keeps that token out of the Referer
        // header on any outbound navigation or subresource from this page,
        // regardless of per-link rel attributes.
        source: "/audit/:path*",
        headers: [{ key: "Referrer-Policy", value: "no-referrer" }],
      },
    ];
  },
};

export default nextConfig;
