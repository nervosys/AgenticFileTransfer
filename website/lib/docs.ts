import fs from "fs";
import path from "path";

const DOCS_DIR = path.join(process.cwd(), "..", "docs");

export function getDoc(filename: string): string {
  const filePath = path.join(DOCS_DIR, filename);
  return fs.readFileSync(filePath, "utf-8");
}
