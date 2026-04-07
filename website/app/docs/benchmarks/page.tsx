import { getDoc } from "@/lib/docs";
import { DocPage } from "@/components/DocPage";

export default function BenchmarksPage() {
  const content = getDoc("BENCHMARKS.md");

  return (
    <DocPage
      title="Benchmarks"
      subtitle="Criterion-based performance benchmarks for primitives, protocol, and transfer I/O"
      classification="UNCLASSIFIED"
      content={content}
    />
  );
}
