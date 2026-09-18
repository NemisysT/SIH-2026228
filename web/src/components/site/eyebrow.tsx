import { cn } from "@/lib/utils";

export function Eyebrow({
  children,
  className,
  tone = "default",
}: {
  children: React.ReactNode;
  className?: string;
  tone?: "default" | "inverted";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-3 text-sm font-mono mb-6",
        tone === "default" ? "text-muted-foreground" : "text-background/60",
        className
      )}
    >
      <span
        className={cn(
          "w-12 h-px origin-left",
          tone === "default" ? "bg-foreground/30" : "bg-background/30"
        )}
      />
      {children}
    </span>
  );
}
