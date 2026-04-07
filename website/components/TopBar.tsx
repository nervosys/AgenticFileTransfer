"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navLinks = [
  { href: "/", label: "Home" },
  { href: "/docs/getting-started", label: "Get Started" },
  { href: "/docs/commands", label: "Commands" },
  { href: "/docs/security", label: "Security" },
  { href: "/docs/benchmarks", label: "Benchmarks" },
  { href: "/docs/changelog", label: "Changelog" },
  { href: "/docs/roadmap", label: "Roadmap" },
];

export function TopBar() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 flex items-center justify-between border-b border-border bg-surface/80 backdrop-blur-md px-6 py-3">
      <Link href="/" className="flex items-center gap-3 group">
        <div className="w-8 h-8 rounded border border-accent flex items-center justify-center glow-border group-hover:bg-accent/10 transition-colors">
          <span className="text-accent font-mono font-bold text-sm">A</span>
        </div>
        <span className="font-mono text-lg font-bold tracking-wider text-foreground">
          AFT<span className="text-accent">.</span>
        </span>
      </Link>

      <nav className="hidden md:flex items-center gap-1">
        {navLinks.map(({ href, label }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`px-3 py-1.5 rounded text-sm font-mono transition-colors ${
                active
                  ? "text-accent bg-accent/10 glow-text"
                  : "text-muted hover:text-foreground hover:bg-surface-light"
              }`}
            >
              {label}
            </Link>
          );
        })}
      </nav>

      <a
        href="https://github.com/nervosys/AgenticFileTransfer"
        target="_blank"
        rel="noopener noreferrer"
        className="text-muted hover:text-accent transition-colors text-sm font-mono"
      >
        GitHub &rarr;
      </a>
    </header>
  );
}
