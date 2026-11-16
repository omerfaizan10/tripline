import type { NextConfig } from "next";

// Fully static: every run page is generated at build time from web/data.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
};

export default nextConfig;
