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
}

export default nextConfig
