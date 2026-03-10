import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "CyberboxSIEM",
  description: "Security Information and Event Management Dashboard",
};

const nav = [
  { href: "/", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/cases", label: "Cases" },
  { href: "/rules", label: "Rules" },
  { href: "/search", label: "NLQ Search" },
  { href: "/coverage", label: "ATT&CK Coverage" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="flex h-screen bg-gray-950 text-gray-100">
          <aside className="w-56 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
            <div className="px-4 py-5 border-b border-gray-800">
              <span className="text-blue-400 font-bold text-lg tracking-tight">
                CyberboxSIEM
              </span>
            </div>
            <nav className="flex-1 px-2 py-4 space-y-1">
              {nav.map(({ href, label }) => (
                <Link
                  key={href}
                  href={href}
                  className="block px-3 py-2 rounded-md text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-800 transition-colors"
                >
                  {label}
                </Link>
              ))}
            </nav>
            <div className="px-4 py-3 border-t border-gray-800 text-xs text-gray-500">
              tenant: default
            </div>
          </aside>
          <main className="flex-1 overflow-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}
