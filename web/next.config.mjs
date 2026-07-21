/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [
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
