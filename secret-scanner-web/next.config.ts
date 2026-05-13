import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: false,
  bundlePagesRouterDependencies: true,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Cross-Origin-Opener-Policy',
            value: 'same-origin-allow-popups',
          },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: '/poc/hetty/:path*',
        destination: `${process.env.POC_PROXY_URL || 'http://poc-proxy'}/poc/hetty/:path*`,
      },
      {
        source: '/poc/mitmweb/:path*',
        destination: `${process.env.POC_PROXY_URL || 'http://poc-proxy'}/poc/mitmweb/:path*`,
      },
    ];
  },
};

export default nextConfig;
