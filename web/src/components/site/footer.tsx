import Link from "next/link";

export function Footer() {
  return (
    <footer className="relative border-t border-foreground/10">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12 py-16">
        <div className="grid gap-12 lg:grid-cols-12">
          <div className="lg:col-span-5">
            <span className="font-display text-2xl tracking-tight text-foreground">
              cvtrust
            </span>
            <p className="mt-4 text-sm text-muted-foreground leading-relaxed max-w-sm">
              Offline dataset forensics for multi-contributor computer vision
              pipelines. Cryptographic manifests, calibrated detectors,
              evidence you can recompute — no network required at run time.
            </p>
          </div>
          <div className="lg:col-span-3">
            <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
              Platform
            </span>
            <ul className="mt-4 space-y-3 text-sm">
              <li>
                <Link href="/#pipeline" className="text-foreground/70 hover:text-foreground transition-colors">
                  Pipeline
                </Link>
              </li>
              <li>
                <Link href="/#detectors" className="text-foreground/70 hover:text-foreground transition-colors">
                  Detectors
                </Link>
              </li>
              <li>
                <Link href="/#coverage" className="text-foreground/70 hover:text-foreground transition-colors">
                  Coverage
                </Link>
              </li>
              <li>
                <Link href="/dashboard" className="text-foreground/70 hover:text-foreground transition-colors">
                  Dashboard
                </Link>
              </li>
            </ul>
          </div>
          <div className="lg:col-span-4">
            <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
              Build
            </span>
            <ul className="mt-4 space-y-3 text-sm text-foreground/70">
              <li>SIH26228 — Module 1: dataset forensics</li>
              <li>Air-gapped runtime, no telemetry</li>
              <li>Ed25519-signature-ready manifests</li>
            </ul>
          </div>
        </div>
        <div className="mt-16 pt-8 border-t border-foreground/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <span className="text-xs text-muted-foreground font-mono">
            cvtrust — Trustworthy Computer Vision Integrity Assurance
          </span>
          <span className="text-xs text-muted-foreground font-mono">
            Module 1 of 5 implemented
          </span>
        </div>
      </div>
    </footer>
  );
}
