import { MarkdownRenderer } from "./MarkdownRenderer";

interface DocPageProps {
  title: string;
  subtitle: string;
  classification?: string;
  content: string;
}

export function DocPage({
  title,
  subtitle,
  classification,
  content,
}: DocPageProps) {
  return (
    <article>
      {/* Header */}
      <div className="mb-8 pb-6 border-b border-border">
        {classification && (
          <div className="inline-flex items-center gap-2 mb-4 px-3 py-1 rounded border border-accent-dim bg-accent/5 text-accent text-xs font-mono uppercase tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
            {classification}
          </div>
        )}
        <h1 className="text-3xl md:text-4xl font-bold text-foreground mb-2 tracking-tight">
          {title}
        </h1>
        <p className="text-muted text-base">{subtitle}</p>
      </div>

      {/* Content */}
      <MarkdownRenderer content={content} />
    </article>
  );
}
