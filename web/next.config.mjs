/** @type {import('next').NextConfig} */
const nextConfig = {
  // The reference shipped with type errors ignored. Module 5 is the type gate
  // for the analyst data layer, so the build fails on a type error instead.
  typescript: {
    ignoreBuildErrors: false,
  },
  images: {
    unoptimized: true,
  },
  // Container packaging only, set by the Dockerfile's web stage.
  //
  // `output: "standalone"` emits .next/standalone/server.js: the same compiled
  // application with only the traced closure of node_modules beside it, ~38 MB
  // instead of ~550 MB. That matters for a deployed image's size and cold-start
  // time, and for nothing else — the routes, the force-dynamic rendering and
  // the filesystem data source are identical either way.
  //
  // It is OFF by default because `next start` refuses to serve a standalone
  // build, and `next start` is what web/package.json, ../run.sh and
  // ../scripts/module5-verify.sh use. Every local command therefore behaves
  // exactly as it did; only the image is packaged differently.
  ...(process.env.NEXT_OUTPUT_STANDALONE === "1" ? { output: "standalone" } : {}),
}

export default nextConfig
