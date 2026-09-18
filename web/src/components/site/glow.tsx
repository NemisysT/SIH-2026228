import { cn } from "@/lib/utils";

/** Ambient blurred glow orb — decorative only, mirrors the reference's subtle background treatment. */
export function Glow({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        "absolute rounded-full bg-foreground/[0.03] blur-[100px] pointer-events-none",
        className
      )}
    />
  );
}
