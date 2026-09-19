"use client"

import { usePathname, useRouter, useSearchParams } from "next/navigation"

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export interface SwitcherOption {
  name: string
  label: string
  disposition: string
  status: string
}

/**
 * Change which scenario every page is showing.
 *
 * The scenario lives in the query string rather than in client state so that a
 * screen an analyst is looking at can be linked to, reloaded, or put on a
 * projector, and still be the same screen. NOT_RUN scenarios stay selectable —
 * their page explains why they did not run, which is worth seeing.
 */
export function ScenarioSwitcher({
  options,
  value,
  source,
}: {
  options: SwitcherOption[]
  value: string
  source: "DEMO" | "LIVE"
}) {
  const router = useRouter()
  const pathname = usePathname()
  const params = useSearchParams()

  function onChange(next: string) {
    const query = new URLSearchParams(params.toString())
    query.set("scenario", next)
    if (source === "LIVE") query.set("source", "live")
    router.push(`${pathname}?${query.toString()}`)
  }

  if (options.length === 0) return null

  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger
        aria-label="Scenario"
        className="h-9 w-full sm:w-[320px] rounded-none border-white/20 bg-black/40 font-mono text-xs text-white hover:border-white/40 focus:ring-0 focus:ring-offset-0"
      >
        <SelectValue placeholder="Select a scenario" />
      </SelectTrigger>
      <SelectContent className="rounded-none border-foreground/15 font-mono text-xs">
        {options.map((option) => (
          <SelectItem key={option.name} value={option.name} className="rounded-none text-xs">
            {option.label}
            <span className="text-muted-foreground">
              {option.status === "RUN" ? ` · ${option.disposition}` : " · NOT_RUN"}
            </span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
