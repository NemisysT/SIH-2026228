import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Coverage, Disposition, Severity } from "@/lib/api";

const SEVERITY_STYLE: Record<Severity, string> = {
  INFO: "border-foreground/15 text-muted-foreground bg-transparent",
  LOW: "border-foreground/20 text-foreground/70 bg-transparent",
  MEDIUM: "border-highlight/40 text-highlight bg-highlight/10",
  HIGH: "border-destructive/50 text-destructive bg-destructive/10",
  CRITICAL: "border-destructive text-destructive-foreground bg-destructive",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant="outline" className={cn("font-mono rounded-full", SEVERITY_STYLE[severity])}>
      {severity}
    </Badge>
  );
}

const DISPOSITION_STYLE: Record<Disposition, string> = {
  ACCEPT: "border-foreground/20 text-muted-foreground bg-transparent",
  REVIEW: "border-highlight/40 text-highlight bg-highlight/10",
  QUARANTINE: "border-destructive text-destructive-foreground bg-destructive",
};

export function DispositionBadge({ disposition }: { disposition: Disposition }) {
  return (
    <Badge variant="outline" className={cn("font-mono rounded-full", DISPOSITION_STYLE[disposition])}>
      {disposition}
    </Badge>
  );
}

const COVERAGE_STYLE: Record<Coverage, string> = {
  SUPPORTED: "border-highlight/40 text-highlight bg-highlight/10",
  PARTIAL: "border-foreground/25 text-foreground/80 bg-transparent",
  NOT_SUPPORTED: "border-foreground/15 text-muted-foreground bg-transparent",
  NOT_ASSESSED: "border-foreground/15 text-muted-foreground bg-transparent",
  REQUIRES_WHITE_BOX: "border-foreground/15 text-muted-foreground bg-transparent",
};

export function CoverageBadge({ coverage }: { coverage: Coverage }) {
  return (
    <Badge variant="outline" className={cn("font-mono rounded-full text-[10px]", COVERAGE_STYLE[coverage])}>
      {coverage.replace(/_/g, " ")}
    </Badge>
  );
}

const OVERALL_STYLE: Record<string, string> = {
  "NO ACTIONABLE FINDINGS": "border-foreground/25 text-foreground bg-transparent",
  "REVIEW RECOMMENDED": "border-highlight/40 text-highlight bg-highlight/10",
  "REVIEW REQUIRED": "border-highlight/60 text-highlight bg-highlight/15",
  "QUARANTINE REQUIRED": "border-destructive text-destructive-foreground bg-destructive",
};

export function OverallBadge({ overall }: { overall: string }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "font-mono rounded-full text-sm px-3 py-1 h-auto",
        OVERALL_STYLE[overall] ?? "border-foreground/20 text-foreground"
      )}
    >
      {overall}
    </Badge>
  );
}
