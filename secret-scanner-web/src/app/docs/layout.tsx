import type { Metadata } from "next";
import { DocsSidebar } from "@/components/docs/docs-sidebar";

export const metadata: Metadata = {
  title: "Documentation — Quantara Security",
  description: "Complete documentation for the Quantara OWASP Security Scanner platform. Guides, tutorials, scanner module references, and knowledge base.",
};

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="min-h-screen flex"
      style={{ background: "#0B0F0C" }}
    >
      <DocsSidebar />
      <main className="flex-1 min-w-0 overflow-hidden">
        {children}
      </main>
    </div>
  );
}
