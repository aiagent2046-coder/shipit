/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async redirects() {
    return [{ source: "/scanner", destination: "/scanner/index.html", permanent: false }];
  },
  async headers() {
    return [
      {
        // Baseline security headers on every frontend response. DENY is safe:
        // the frontend is never embedded in an iframe. No ENFORCING CSP here —
        // a correct Next.js CSP needs a nonce-based script policy (Next
        // injects inline runtime scripts) and is deferred as a dedicated
        // follow-up. The Report-Only policy below is that follow-up's first
        // step: it names the target policy and surfaces its real violations
        // (the inline runtime scripts above all) in browser consoles while
        // blocking nothing. /scanner keeps its own stricter ENFORCING CSP
        // from the block below; a Report-Only header alongside an enforcing
        // one adds reports, never removes restrictions.
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains",
          },
          {
            key: "Content-Security-Policy-Report-Only",
            value: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.drydock.co; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
          },
        ],
      },
      {
        source: "/scanner/:path*",
        headers: [
          { key: "Content-Security-Policy", value: "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Cache-Control", value: "no-cache" },
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
