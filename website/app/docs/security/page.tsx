import { getDoc } from "@/lib/docs";
import { DocPage } from "@/components/DocPage";

export default function SecurityPage() {
  const content = getDoc("SECURITY.md");

  return (
    <DocPage
      title="Security Audit Report"
      subtitle="CVE patterns, MITRE ATT&CK, NIST FIPS 140-3, CMMC 2.0 Level 2 assessment"
      classification="CUI // FOUO"
      content={content}
    />
  );
}
