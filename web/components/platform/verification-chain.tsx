import { humanise, text } from "@/lib/analyst/format"
import type { StageView } from "@/lib/analyst/provenance"

import { CheckMark, Panel, Tag } from "./primitives"

/**
 * The verification pipeline for one record.
 *
 * §10 is explicit that a failure must not be a red FAILED badge: it must name
 * the check, the artifact, the observation and the verifier's own detail. So a
 * failing stage renders expanded, with every check it contains and the raw
 * observation object the verifier recorded.
 *
 * A stage whose checks did not run is neutral, not failed. Painting
 * NOT_APPLICABLE red would misreport coverage as compromise.
 */
export function VerificationChain({ stages }: { stages: StageView[] }) {
  return (
    <ol className="space-y-3">
      {stages.map((stage, index) => (
        <li key={stage.id}>
          <Panel
            className={`p-5 ${stage.state === "FAIL" ? "border-destructive/50 bg-destructive/[0.04]" : ""}`}
          >
            <details open={stage.state === "FAIL"} className="group">
              <summary className="cursor-pointer list-none flex flex-wrap items-center gap-3">
                <span className="font-mono text-xs text-muted-foreground w-6 shrink-0">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <CheckMark state={stage.state} />
                <span className="font-medium flex-1 min-w-0">{stage.label}</span>
                <Tag active={stage.state === "FAIL"}>
                  {stage.state === "PASS"
                    ? "VERIFIED"
                    : stage.state === "FAIL"
                      ? "FAILED"
                      : "NOT ASSESSED"}
                </Tag>
                <span
                  aria-hidden="true"
                  className="text-muted-foreground group-open:rotate-90 transition-transform"
                >
                  &rsaquo;
                </span>
              </summary>

              <div className="mt-5 space-y-4 pl-9">
                {stage.checks.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    None of this stage&rsquo;s checks ran for this record. The absence of a result
                    is not a pass.
                  </p>
                ) : (
                  stage.checks.map((check) => (
                    <div key={check.name} className="border-l border-foreground/15 pl-4">
                      <div className="flex flex-wrap items-center gap-3 mb-1">
                        <span className="font-mono text-xs">{humanise(check.name)}</span>
                        <Tag>{text(check.outcome, "NO OUTCOME")}</Tag>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        {text(check.detail, "")}
                      </p>
                      {check.observation && Object.keys(check.observation).length > 0 ? (
                        <pre className="mt-2 text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-3 overflow-x-auto max-h-56">
                          {JSON.stringify(check.observation, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  ))
                )}
                {stage.absent.length > 0 ? (
                  <p className="text-xs font-mono text-muted-foreground">
                    not present in this verification: {stage.absent.join(", ")}
                  </p>
                ) : null}
              </div>
            </details>
          </Panel>
        </li>
      ))}
    </ol>
  )
}
