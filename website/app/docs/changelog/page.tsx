import { getDoc } from "@/lib/docs";
import { DocPage } from "@/components/DocPage";

export default function ChangelogPage() {
  const content = getDoc("CHANGELOG.md");

  return (
    <DocPage
      title="Changelog"
      subtitle="All notable changes to AFT, following Keep a Changelog and Semantic Versioning"
      content={content}
    />
  );
}
