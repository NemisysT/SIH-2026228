"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

const LINKS = [
  { href: "/#pipeline", label: "Pipeline" },
  { href: "/#detectors", label: "Detectors" },
  { href: "/#evidence", label: "Evidence" },
  { href: "/#coverage", label: "Coverage" },
];

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header className="fixed z-50 transition-all duration-500 top-0 left-0 right-0">
      <nav
        className={`mx-auto transition-all duration-500 max-w-[1400px] ${
          scrolled
            ? "bg-background/80 backdrop-blur-xl border-b border-foreground/10"
            : "bg-transparent"
        }`}
      >
        <div
          className={`flex items-center justify-between transition-all duration-500 px-6 lg:px-8 ${
            scrolled ? "h-16" : "h-20"
          }`}
        >
          <Link href="/" className="flex items-center gap-2 group">
            <span className="font-display tracking-tight transition-all duration-500 text-2xl text-foreground">
              cvtrust
            </span>
            <span className="font-mono transition-all duration-500 text-[10px] mt-1 text-foreground/40 border border-foreground/20 rounded-full px-1.5 py-0.5">
              M1
            </span>
          </Link>
          <div className="hidden md:flex items-center gap-10">
            {LINKS.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                className="text-sm transition-colors duration-300 relative group text-foreground/70 hover:text-foreground"
              >
                {l.label}
                <span className="absolute -bottom-1 left-0 w-0 h-px transition-all duration-300 group-hover:w-full bg-foreground" />
              </Link>
            ))}
          </div>
          <div className="hidden md:flex items-center gap-4">
            <Link
              href="/dashboard"
              className="transition-all duration-500 text-sm text-foreground/70 hover:text-foreground"
            >
              Dashboard
            </Link>
            <Button
              size="sm"
              className="rounded-full px-6"
              render={<Link href="/dashboard">Run demo</Link>}
            />
          </div>

          <Sheet>
            <SheetTrigger
              render={
                <Button
                  variant="ghost"
                  size="icon"
                  className="md:hidden text-foreground"
                  aria-label="Toggle menu"
                >
                  <Menu className="size-5" />
                </Button>
              }
            />
            <SheetContent side="right" className="bg-background border-foreground/10 w-3/4">
              <SheetHeader>
                <SheetTitle className="font-display text-xl">cvtrust</SheetTitle>
              </SheetHeader>
              <nav className="flex flex-col gap-1 px-4">
                {LINKS.map((l) => (
                  <SheetClose
                    key={l.href}
                    render={
                      <Link
                        href={l.href}
                        className="py-3 text-base text-foreground/80 hover:text-foreground border-b border-foreground/5"
                      >
                        {l.label}
                      </Link>
                    }
                  />
                ))}
                <SheetClose
                  render={
                    <Link
                      href="/dashboard"
                      className="py-3 text-base text-foreground/80 hover:text-foreground border-b border-foreground/5"
                    >
                      Dashboard
                    </Link>
                  }
                />
              </nav>
              <div className="px-4 mt-4">
                <Button
                  className="rounded-full w-full"
                  render={<Link href="/dashboard">Run demo</Link>}
                />
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </nav>
    </header>
  );
}
