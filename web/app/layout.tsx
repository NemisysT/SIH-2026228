import React from "react"
import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SIH26228 — CV Integrity Assurance',
  description:
    'Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines. Analyst platform for the cvtrust assurance engine (Modules 1-4).',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        {children}
      </body>
    </html>
  )
}
