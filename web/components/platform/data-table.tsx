import type { ReactNode } from "react"

/**
 * The reference's table, wrapped so column definitions stay declarative.
 *
 * Uses the shadcn table the reference already ships, with the platform's
 * hairline borders. Every cell renders whatever the projection handed it —
 * including an em dash for a value the engine did not produce, which is the
 * honest rendering of a missing number.
 */
export interface Column<Row> {
  key: string
  header: string
  render: (row: Row) => ReactNode
  className?: string
  numeric?: boolean
}

export function DataTable<Row>({
  columns,
  rows,
  rowKey,
  empty = "Nothing to show.",
  caption,
}: {
  columns: Column<Row>[]
  rows: Row[]
  rowKey: (row: Row, index: number) => string
  empty?: string
  caption?: string
}) {
  if (rows.length === 0) {
    return <p className="text-sm text-muted-foreground">{empty}</p>
  }
  return (
    <div className="w-full overflow-x-auto border border-foreground/10">
      <table className="w-full min-w-[640px] caption-bottom text-sm">
        {caption ? (
          <caption className="p-4 text-left text-xs font-mono text-muted-foreground">
            {caption}
          </caption>
        ) : null}
        <thead>
          <tr className="border-b border-foreground/10 bg-foreground/[0.02]">
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                className={`px-4 py-3 text-left text-[11px] font-mono uppercase tracking-wider text-muted-foreground whitespace-nowrap ${
                  column.numeric ? "text-right" : ""
                } ${column.className ?? ""}`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey(row, index)}
              className="border-b border-foreground/5 last:border-0 hover:bg-foreground/[0.03] transition-colors"
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={`px-4 py-3 align-top ${column.numeric ? "text-right tabular-nums" : ""} ${
                    column.className ?? ""
                  }`}
                >
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
