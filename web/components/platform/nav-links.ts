/** The analyst platform's information architecture (§5), in one place. */
export interface NavLink {
  name: string
  href: string
  description: string
}

/** The links the top bar shows, occupying the same slot as the reference's. */
export const PRIMARY_LINKS: NavLink[] = [
  { name: "Dataset", href: "/dataset", description: "Module 1 dataset forensics" },
  { name: "Model", href: "/model", description: "Module 2 model forensics" },
  { name: "Provenance", href: "/provenance", description: "Module 3 inference provenance" },
  { name: "Audit", href: "/audit", description: "Module 3 chain and signing trail" },
  { name: "Shift", href: "/shift", description: "Module 4 distribution shift" },
  { name: "Evidence", href: "/evidence", description: "Evidence lineage explorer" },
  { name: "Coverage", href: "/coverage", description: "What was and was not assessed" },
]

/** Everything, for the footer columns and the mobile menu. */
export const ALL_AREAS: Record<string, NavLink[]> = {
  Assurance: [
    { name: "Overview", href: "/", description: "Assurance dashboard" },
    { name: "Assurance decision", href: "/decision", description: "Disposition and why" },
    { name: "Evidence explorer", href: "/evidence", description: "Decision to raw observation" },
    { name: "Coverage", href: "/coverage", description: "Assessed and not assessed" },
  ],
  Forensics: [
    { name: "Dataset forensics", href: "/dataset", description: "Module 1" },
    { name: "Model forensics", href: "/model", description: "Module 2" },
    { name: "Inference provenance", href: "/provenance", description: "Module 3" },
    { name: "Distribution shift", href: "/shift", description: "Module 4" },
  ],
  Records: [
    { name: "Audit trail", href: "/audit", description: "Chain, keys, replay" },
    { name: "Scenarios", href: "/demo", description: "The scenario matrix for the active source" },
  ],
}
