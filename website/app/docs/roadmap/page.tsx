import { getDoc } from "@/lib/docs";
import { DocPage } from "@/components/DocPage";

export default function RoadmapPage() {
  const content = getDoc("ROADMAP.md");

  return (
    <DocPage
      title="Roadmap"
      subtitle="Implementation progress across all phases of AFT development"
      content={content}
    />
  );
}
