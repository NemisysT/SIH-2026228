import { Skeleton } from "@/components/ui/skeleton"

/**
 * The loading state, using the reference's own skeleton primitive.
 *
 * Every analyst page is server-rendered from reports on disk, and the largest
 * scenario's report is over a megabyte. This mirrors the page frame — black
 * hero plate with its hairline grid, then the content rail — so the layout
 * does not jump when the data lands. The reference has no spinner and neither
 * does this.
 */
export default function Loading() {
  return (
    <main className="relative min-h-screen overflow-x-hidden" aria-busy="true">
      <div className="relative min-h-[62vh] lg:min-h-[68vh] flex flex-col justify-center bg-black overflow-hidden">
        <div className="absolute inset-0 z-0">
          <div className="absolute inset-0 bg-gradient-to-r from-black via-black/90 to-black/70" />
          <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-black/80" />
        </div>
        <div className="absolute inset-0 z-[2] overflow-hidden pointer-events-none opacity-20">
          {[...Array(8)].map((_, i) => (
            <div
              key={`h-${i}`}
              className="absolute h-px bg-white/10"
              style={{ top: `${12.5 * (i + 1)}%`, left: 0, right: 0 }}
            />
          ))}
          {[...Array(12)].map((_, i) => (
            <div
              key={`v-${i}`}
              className="absolute w-px bg-white/10"
              style={{ left: `${8.33 * (i + 1)}%`, top: 0, bottom: 0 }}
            />
          ))}
        </div>

        <div className="relative z-10 w-full max-w-[1400px] mx-auto px-6 lg:px-12 pt-36 pb-24 lg:pt-44 lg:pb-32">
          <Skeleton className="h-4 w-64 bg-white/10 rounded-none mb-8" />
          <Skeleton className="h-16 lg:h-24 w-full max-w-3xl bg-white/10 rounded-none mb-4" />
          <Skeleton className="h-16 lg:h-24 w-full max-w-xl bg-white/10 rounded-none mb-10" />
          <Skeleton className="h-20 w-full bg-white/5 rounded-none" />
        </div>
      </div>

      <section className="relative py-20 lg:py-28">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
          <Skeleton className="h-4 w-40 rounded-none mb-6" />
          <Skeleton className="h-20 w-full max-w-2xl rounded-none mb-16" />
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-56 w-full rounded-none" />
            ))}
          </div>
        </div>
      </section>

      <span className="sr-only">Loading the assurance report</span>
    </main>
  )
}
