import { ArrowUpRight } from "lucide-react"
import Link from "next/link"

import { ALL_AREAS } from "./nav-links"

/**
 * The reference footer, carrying the platform's own information architecture.
 *
 * The panoramic banner with its fade-to-black, the black plate, the brand
 * column, the four link columns and the bottom bar are the reference's, class
 * for class. The banner image is the supplied asset, served locally.
 */
export function PlatformFooter({
  suffix = "",
  softwareVersion,
  generatedAt,
  policyVersion,
}: {
  suffix?: string
  softwareVersion?: string | null
  generatedAt?: string | null
  policyVersion?: string | null
}) {
  return (
    <footer className="relative bg-black">
      {/* Panoramic banner image */}
      <div className="relative w-full h-[340px] md:h-[420px] overflow-hidden">
        <img
          src="/images/footer-banner.png"
          alt=""
          aria-hidden="true"
          className="w-full h-full object-cover object-center"
        />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-black" />
        <div className="absolute inset-0 bg-gradient-to-r from-black/40 via-transparent to-black/40" />
      </div>

      <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
        <div className="py-16 lg:py-20">
          <div className="grid grid-cols-2 md:grid-cols-6 gap-12 lg:gap-8">
            {/* Brand Column */}
            <div className="col-span-2">
              <Link href={`/${suffix}`} className="inline-flex items-center gap-2 mb-6">
                <span className="text-2xl font-display text-white">CVTRUST</span>
                <span className="text-xs text-white/40 font-mono">SIH26228</span>
              </Link>

              <p className="text-white/50 leading-relaxed mb-4 max-w-xs text-sm">
                Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference
                Outputs in Multi-Contributor Pipelines.
              </p>
              <p className="text-white/30 leading-relaxed mb-8 max-w-xs text-xs font-mono">
                Smart India Hackathon 2026 · Problem statement SIH26228
              </p>

              <div className="flex flex-col gap-2 text-xs font-mono text-white/30">
                <span>Engine {softwareVersion ?? "—"}</span>
                <span>Policy {policyVersion ?? "—"}</span>
                <span>Feed {generatedAt ?? "—"}</span>
              </div>
            </div>

            {/* Link Columns */}
            {Object.entries(ALL_AREAS).map(([title, links]) => (
              <div key={title}>
                <h3 className="text-sm font-medium text-white mb-6">{title}</h3>
                <ul className="space-y-4">
                  {links.map((link) => (
                    <li key={link.href}>
                      <Link
                        href={`${link.href}${suffix}`}
                        className="text-sm text-white/40 hover:text-white transition-colors inline-flex items-center gap-1 group"
                      >
                        {link.name}
                        <ArrowUpRight
                          aria-hidden="true"
                          className="w-3 h-3 opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all"
                        />
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}

            <div>
              <h3 className="text-sm font-medium text-white mb-6">Reports</h3>
              <ul className="space-y-4">
                <li>
                  <Link
                    href={`/decision${suffix}`}
                    className="text-sm text-white/40 hover:text-white transition-colors"
                  >
                    Assurance report
                  </Link>
                </li>
                <li>
                  <Link
                    href={`/coverage${suffix}`}
                    className="text-sm text-white/40 hover:text-white transition-colors"
                  >
                    Limitations
                  </Link>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="py-8 border-t border-white/10 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-white/30">
            Runs offline. No cloud service, no telemetry, no external API.
          </p>

          <div className="flex items-center gap-4 text-sm text-white/30">
            <span className="flex items-center gap-2">
              <span aria-hidden="true" className="w-2 h-2 rounded-full bg-[#eca8d6]" />
              No universal trust score is computed anywhere in this system.
            </span>
          </div>
        </div>
      </div>
    </footer>
  )
}
