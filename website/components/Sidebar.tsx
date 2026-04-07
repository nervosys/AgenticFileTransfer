"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

interface NavSection {
  title: string;
  items: { href: string; label: string; icon: string }[];
}

const sections: NavSection[] = [
  {
    title: "Overview",
    items: [
      { href: "/", label: "Home", icon: "◈" },
    ],
  },
  {
    title: "Documentation",
    items: [
      { href: "/docs/getting-started", label: "Getting Started", icon: "⚡" },
      { href: "/docs/commands", label: "Commands", icon: "⌘" },
      { href: "/docs/security", label: "Security Audit", icon: "⛨" },
      { href: "/docs/benchmarks", label: "Benchmarks", icon: "◉" },
      { href: "/docs/changelog", label: "Changelog", icon: "◆" },
      { href: "/docs/roadmap", label: "Roadmap", icon: "▸" },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`hidden lg:flex flex-col border-r border-border bg-surface/60 backdrop-blur-sm transition-all duration-300 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      <div className="flex items-center justify-end p-3">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-muted hover:text-accent transition-colors text-xs font-mono"
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? "»" : "«"}
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-6">
        {sections.map((section) => (
          <div key={section.title} className="mb-6">
            {!collapsed && (
              <h3 className="text-[10px] font-mono uppercase tracking-[0.2em] text-accent-dim mb-2 px-2">
                {section.title}
              </h3>
            )}
            {section.items.map(({ href, label, icon }) => {
              const active = pathname === href;
              return (
                <Link
                  key={href}
                  href={href}
                  className={`flex items-center gap-3 px-2 py-2 rounded text-sm font-mono transition-all ${
                    active
                      ? "text-accent bg-accent/10 glow-border"
                      : "text-muted hover:text-foreground hover:bg-surface-light"
                  }`}
                  title={label}
                >
                  <span className={`text-base ${active ? "glow-text" : ""}`}>
                    {icon}
                  </span>
                  {!collapsed && <span>{label}</span>}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Status indicator */}
      <div className="p-3 border-t border-border">
        <div className="flex items-center gap-2 px-2">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          {!collapsed && (
            <span className="text-[11px] font-mono text-muted">v1.3.0</span>
          )}
        </div>
      </div>
    </aside>
  );
}
