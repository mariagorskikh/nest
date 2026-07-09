import type { NextConfig } from "next";

// The migrated NandaHack guide pages are plain HTML under public/; Next
// does not resolve directory indexes there, so map each section URL to
// its index.html.
const staticPages = [
  "guides", "guides/demo", "guides/skillmd",
  "onboarding", "onboarding/startups", "onboarding/individuals",
  "onboarding/companies", "onboarding/submit",
  "showcase", "showcase/admin",
];

const nextConfig: NextConfig = {
  async rewrites() {
    return staticPages.map((p) => ({
      source: `/${p}`,
      destination: `/${p}/index.html`,
    }));
  },
};

export default nextConfig;
