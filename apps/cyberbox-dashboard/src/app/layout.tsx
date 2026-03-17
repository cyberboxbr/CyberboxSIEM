import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import { previewTenant } from "@/lib/api";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Cyberbox Dashboard Preview",
  description: "Internal preview console for the Cyberbox SIEM API",
};

const nav = [
  { href: "/", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/cases", label: "Cases" },
  { href: "/rules", label: "Rules" },
  { href: "/search", label: "NLQ Search" },
  { href: "/coverage", label: "ATT&CK Coverage" },
];

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="flex h-screen bg-gray-950 text-gray-100">
          <aside className="flex w-56 shrink-0 flex-col border-r border-gray-800 bg-gray-900">
            <div className="border-b border-gray-800 px-4 py-5">
              <span className="text-lg font-bold tracking-tight text-blue-400">
                Cyberbox Preview
              </span>
            </div>
            <div className="border-b border-amber-900/60 bg-amber-950/50 px-4 py-3 text-xs text-amber-200">
              Internal preview. The supported operator UI remains <code>web/cyberbox-ui</code>.
            </div>
            <nav className="flex-1 space-y-1 px-2 py-4">
              {nav.map(({ href, label }) => (
                <Link
                  key={href}
                  href={href}
                  className="block rounded-md px-3 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-gray-800 hover:text-white"
                >
                  {label}
                </Link>
              ))}
            </nav>
            <div className="border-t border-gray-800 px-4 py-3 text-xs text-gray-500">
              tenant: {previewTenant()}
            </div>
          </aside>
          <main className="flex-1 overflow-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}
