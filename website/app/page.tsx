import Link from "next/link";

const features = [
  {
    icon: "⛨",
    title: "DoD-Grade Security",
    desc: "MITRE ATT&CK, NIST FIPS 140-3, CMMC 2.0 Level 2 audited. Auth rate limiting, TLS 1.2+, structured audit logging.",
  },
  {
    icon: "◈",
    title: "Post-Quantum Crypto",
    desc: "Kyber1024 KEM + AES-256-GCM AEAD. NIST FIPS 203 ML-KEM key encapsulation for quantum-resistant file protection.",
  },
  {
    icon: "◉",
    title: "15 GiB/s CRC32",
    desc: "Hardware-accelerated SSE4.2 / AES-NI / SHA-NI primitives. Per-frame integrity, streaming SHA-256, zero-copy mmap.",
  },
  {
    icon: "▸",
    title: "Turbo Engine",
    desc: "Adaptive multi-stream transfers. Dynamic mode selection, 128 parallel streams, 16 MiB socket tuning, memory-mapped I/O.",
  },
  {
    icon: "◆",
    title: "12+ Protocols",
    desc: "HTTP/S, FTP/S, SFTP, S3, WebDAV, Azure Blob, GCS, SMB, AFTP/S, DoD CDS, local filesystem. Extensible via plugins.",
  },
  {
    icon: "◇",
    title: "Agentic-First",
    desc: "JSON output, self-describing ontology, structured error schema. Built for AI agent tool discovery and orchestration.",
  },
];

const stats = [
  { value: "322", label: "Tests" },
  { value: "12+", label: "Protocols" },
  { value: "~9 MB", label: "Binary" },
  { value: "0", label: "Runtime Deps" },
];

const docLinks = [
  {
    href: "/docs/getting-started",
    label: "Getting Started",
    desc: "Install, configure, and run your first transfer",
  },
  {
    href: "/docs/commands",
    label: "Commands Reference",
    desc: "All 16 commands, subcommands, and global flags",
  },
  {
    href: "/docs/security",
    label: "Security Audit",
    desc: "CVE, MITRE ATT&CK, FIPS, CMMC 2.0",
  },
  {
    href: "/docs/benchmarks",
    label: "Benchmarks",
    desc: "Criterion performance data",
  },
  {
    href: "/docs/changelog",
    label: "Changelog",
    desc: "Release history and changes",
  },
  {
    href: "/docs/roadmap",
    label: "Roadmap",
    desc: "144 tasks across 17 phases",
  },
];

export default function Home() {
  return (
    <div>
      {/* Hero */}
      <section className="relative mb-16">
        <div className="absolute -top-8 -left-8 w-64 h-64 bg-accent/5 rounded-full blur-3xl pointer-events-none" />
        <div className="relative flex flex-col items-center text-center">
          <div className="inline-flex items-center gap-2 mb-6 px-3 py-1.5 rounded border border-border bg-surface-light text-xs font-mono text-muted">
            <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            v1.3.1 — Turbo Engine &middot; Sync &middot; HW-Accelerated Integrity
          </div>

          <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-foreground mb-4">
            <span className="text-accent glow-text">AFT</span>
            <span className="text-muted font-light"> — </span>
            Agentic File Transfer
          </h1>

          <p className="text-lg md:text-xl text-muted max-w-2xl mx-auto mb-8 leading-relaxed">
            High-performance, protocol-agnostic file transfer CLI for{" "}
            <span className="text-foreground">humans</span> and{" "}
            <span className="text-accent">AI agents</span>. Post-quantum encryption.
            DoD-grade security. ~9 MB binary. Zero runtime dependencies.
          </p>

          <div className="flex flex-wrap justify-center gap-3 mb-12">
            <code className="px-4 py-2 bg-surface border border-border rounded-lg font-mono text-sm text-foreground">
              cargo install --path .
            </code>
          </div>

          {/* Stats bar */}
          <div className="flex flex-wrap justify-center gap-8 pb-8 border-b border-border w-full">
            {stats.map(({ value, label }) => (
              <div key={label}>
                <div className="text-2xl font-bold font-mono text-accent glow-text">
                  {value}
                </div>
                <div className="text-xs font-mono text-muted uppercase tracking-wider">
                  {label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features grid */}
      <section className="mb-16">
        <h2 className="text-sm font-mono uppercase tracking-[0.2em] text-accent-dim mb-6">
          Capabilities
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(({ icon, title, desc }) => (
            <div
              key={title}
              className="p-5 rounded-lg border border-border bg-surface/50 hover:bg-surface-light hover:border-accent-dim transition-all group"
            >
              <div className="text-2xl mb-3 text-accent group-hover:glow-text transition-all">
                {icon}
              </div>
              <h3 className="font-mono text-sm font-semibold text-foreground mb-2">
                {title}
              </h3>
              <p className="text-xs text-muted leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Documentation links */}
      <section className="mb-16">
        <h2 className="text-sm font-mono uppercase tracking-[0.2em] text-accent-dim mb-6">
          Documentation
        </h2>
        <div className="space-y-2">
          {docLinks.map(({ href, label, desc, badge }) => (
            <Link
              key={href}
              href={href}
              className="flex items-center justify-between p-4 rounded-lg border border-border bg-surface/30 hover:bg-surface-light hover:border-accent-dim transition-all group"
            >
              <div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-semibold text-foreground group-hover:text-accent transition-colors">
                    {label}
                  </span>
                  {badge && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border border-accent-dim text-accent-dim">
                      {badge}
                    </span>
                  )}
                </div>
                <span className="text-xs text-muted">{desc}</span>
              </div>
              <span className="text-muted group-hover:text-accent transition-colors font-mono">
                &rarr;
              </span>
            </Link>
          ))}
        </div>
      </section>

      {/* Terminal preview */}
      <section className="mb-16">
        <h2 className="text-sm font-mono uppercase tracking-[0.2em] text-accent-dim mb-6">
          Quick Start
        </h2>
        <div className="rounded-lg border border-border bg-surface overflow-hidden glow-border">
          <div className="flex items-center gap-2 px-4 py-2.5 bg-surface-light border-b border-border">
            <div className="w-3 h-3 rounded-full bg-danger/60" />
            <div className="w-3 h-3 rounded-full bg-warning/60" />
            <div className="w-3 h-3 rounded-full bg-success/60" />
            <span className="ml-3 text-xs font-mono text-muted">terminal</span>
          </div>
          <pre className="p-5 text-sm font-mono overflow-x-auto">
            <code>
              <span className="text-muted"># Download a file</span>
              {"\n"}
              <span className="text-success">$</span>{" "}
              <span className="text-foreground">aft get</span>{" "}
              <span className="text-accent">https://example.com/data.tar.gz</span>
              {"\n\n"}
              <span className="text-muted"># Turbo transfer with 64 parallel streams</span>
              {"\n"}
              <span className="text-success">$</span>{" "}
              <span className="text-foreground">aft get</span>{" "}
              <span className="text-accent">aftp://server:2600/payload.bin</span>{" "}
              <span className="text-warning">--turbo --streams 64</span>
              {"\n\n"}
              <span className="text-muted"># Encrypt with post-quantum crypto</span>
              {"\n"}
              <span className="text-success">$</span>{" "}
              <span className="text-foreground">aft crypto encrypt</span>{" "}
              <span className="text-accent">-i secret.pdf</span>{" "}
              <span className="text-warning">--method pqc -k keys.pub</span>
              {"\n\n"}
              <span className="text-muted"># Sync directories (rsync-class)</span>
              {"\n"}
              <span className="text-success">$</span>{" "}
              <span className="text-foreground">aft sync</span>{" "}
              <span className="text-accent">./src/ sftp://server/backup/</span>{" "}
              <span className="text-warning">--delete --compare checksum</span>
              {"\n\n"}
              <span className="text-muted"># AI agent mode — structured JSON output</span>
              {"\n"}
              <span className="text-success">$</span>{" "}
              <span className="text-foreground">aft --agent capabilities</span>
            </code>
          </pre>
        </div>
      </section>

      {/* Footer */}
      <footer className="pt-8 pb-12 border-t border-border">
        <div className="flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-muted">
          <span>
            &copy; {new Date().getFullYear()} Nervosys &middot; AGPL-3.0-or-later
          </span>
          <span>AFT v1.3.1 &middot; Rust &middot; MSRV 1.75</span>
        </div>
      </footer>
    </div>
  );
}
