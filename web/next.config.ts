import type { NextConfig } from "next";

// The browser only ever talks to this origin. Requests to /v1/* are proxied to the Rekey API, so
// the session cookie is first-party and no CORS is needed. The OIDC redirect URI registered in
// GitLab is therefore https://<ui host>/v1/auth/oidc/callback.
const apiUrl = process.env.REKEY_API_URL ?? "http://127.0.0.1:8780";

const nextConfig: NextConfig = {
  output: "standalone", // a small self-contained server for the Docker image
  async rewrites() {
    return [{ source: "/v1/:path*", destination: `${apiUrl}/v1/:path*` }];
  },
};

export default nextConfig;
