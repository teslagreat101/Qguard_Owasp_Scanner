"use client";

import { useParams } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  ChevronRight,
  ChevronLeft,
  Clock,
  Calendar,
  ArrowRight,
  Home,
  FileText,
  ExternalLink,
} from "lucide-react";
import {
  getArticleBySlug,
  getSectionByArticleSlug,
  getAdjacentArticles,
  allArticles,
} from "@/lib/docs-content";
import { DocsContentRenderer } from "@/components/docs/docs-content-renderer";

export default function DocArticlePage() {
  const params = useParams();
  const slug = params.slug as string;

  const article = getArticleBySlug(slug);
  const section = getSectionByArticleSlug(slug);
  const { prev, next } = getAdjacentArticles(slug);

  if (!article) {
    return <NotFoundPage slug={slug} />;
  }

  // Build TOC from heading blocks
  const tocItems = article.content
    .filter(b => b.type === "heading2" && "id" in b && b.id)
    .map(b => ({ id: (b as { id?: string }).id!, title: (b as { content: string }).content }));

  return (
    <div className="flex min-h-screen">
      {/* Main Content */}
      <div className="flex-1 min-w-0 px-6 lg:px-10 xl:px-14 py-8 lg:py-12 max-w-4xl">

        {/* Breadcrumb */}
        <motion.nav
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="flex items-center gap-1.5 mb-8 flex-wrap"
        >
          <Link
            href="/"
            className="flex items-center gap-1 text-muted-foreground hover:text-primary transition-colors text-xs"
          >
            <Home className="w-3 h-3" />
            Home
          </Link>
          <ChevronRight className="w-3 h-3 text-muted-foreground" />
          <Link
            href="/docs"
            className="text-muted-foreground hover:text-primary transition-colors text-xs"
          >
            Docs
          </Link>
          {section && (
            <>
              <ChevronRight className="w-3 h-3 text-muted-foreground" />
              <span className="text-muted-foreground text-xs">{section.title}</span>
            </>
          )}
          <ChevronRight className="w-3 h-3 text-muted-foreground" />
          <span className="text-muted-foreground text-xs font-medium">{article.title}</span>
        </motion.nav>

        {/* Article Header */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="mb-8"
        >
          {/* Category badge */}
          <div
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full mb-4 text-[10px] font-bold uppercase tracking-widest"
            style={{
              background: "rgba(0,255,136,0.06)",
              border: "1px solid rgba(0,255,136,0.2)",
              color: "#00FF88",
            }}
          >
            <FileText className="w-3 h-3" />
            {article.category}
          </div>

          <h1 className="text-3xl lg:text-4xl font-black text-foreground font-outfit tracking-tight leading-tight mb-4">
            {article.title}
          </h1>

          <p className="text-muted-foreground text-lg leading-relaxed mb-5">
            {article.description}
          </p>

          {/* Meta row */}
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
              <Clock className="w-3.5 h-3.5" />
              {article.estimatedRead} min read
            </div>
            <div className="flex items-center gap-1.5 text-muted-foreground text-xs">
              <Calendar className="w-3.5 h-3.5" />
              Updated {article.lastUpdated}
            </div>
          </div>

          {/* Divider */}
          <div
            className="mt-6 h-px"
            style={{ background: "linear-gradient(to right, rgba(0,255,136,0.3), rgba(0,255,136,0.05), transparent)" }}
          />
        </motion.div>

        {/* Article Content */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.1 }}
        >
          <DocsContentRenderer blocks={article.content} />
        </motion.div>

        {/* Bottom divider */}
        <div
          className="mt-12 mb-8 h-px"
          style={{ background: "linear-gradient(to right, rgba(0,255,136,0.1), transparent)" }}
        />

        {/* Prev / Next Navigation */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {prev ? (
            <Link
              href={`/docs/${prev.slug}`}
              className="group p-4 rounded-xl transition-all duration-300"
              style={{
                background: "rgba(0,255,136,0.02)",
                border: "1px solid rgba(0,255,136,0.08)",
              }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,255,136,0.2)";
                (e.currentTarget as HTMLAnchorElement).style.background = "rgba(0,255,136,0.04)";
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,255,136,0.08)";
                (e.currentTarget as HTMLAnchorElement).style.background = "rgba(0,255,136,0.02)";
              }}
            >
              <div className="flex items-center gap-2 text-muted-foreground text-[10px] uppercase tracking-widest font-bold mb-2">
                <ChevronLeft className="w-3.5 h-3.5" />
                Previous
              </div>
              <p className="text-foreground text-sm font-medium group-hover:text-primary transition-colors">
                {prev.title}
              </p>
            </Link>
          ) : (
            <div />
          )}

          {next ? (
            <Link
              href={`/docs/${next.slug}`}
              className="group p-4 rounded-xl transition-all duration-300 text-right"
              style={{
                background: "rgba(0,255,136,0.02)",
                border: "1px solid rgba(0,255,136,0.08)",
              }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,255,136,0.2)";
                (e.currentTarget as HTMLAnchorElement).style.background = "rgba(0,255,136,0.04)";
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLAnchorElement).style.borderColor = "rgba(0,255,136,0.08)";
                (e.currentTarget as HTMLAnchorElement).style.background = "rgba(0,255,136,0.02)";
              }}
            >
              <div className="flex items-center justify-end gap-2 text-muted-foreground text-[10px] uppercase tracking-widest font-bold mb-2">
                Next
                <ChevronRight className="w-3.5 h-3.5" />
              </div>
              <p className="text-foreground text-sm font-medium group-hover:text-primary transition-colors">
                {next.title}
              </p>
            </Link>
          ) : (
            <div />
          )}
        </div>

        {/* Footer padding */}
        <div className="h-20" />
      </div>

      {/* Right Rail — Table of Contents */}
      {tocItems.length > 0 && (
        <aside className="hidden xl:block w-56 flex-shrink-0 pl-4 py-12 pr-6">
          <div className="sticky top-12">
            <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-4">
              On this page
            </p>
            <nav className="space-y-1">
              {tocItems.map(item => (
                <a
                  key={item.id}
                  href={`#${item.id}`}
                  className="block text-xs text-muted-foreground hover:text-primary transition-colors py-1 leading-snug"
                >
                  {item.title}
                </a>
              ))}
            </nav>

            {/* Help box */}
            <div
              className="mt-8 p-4 rounded-xl"
              style={{
                background: "rgba(0,255,136,0.03)",
                border: "1px solid rgba(0,255,136,0.1)",
              }}
            >
              <p className="text-[11px] font-semibold text-foreground mb-1.5">Need help?</p>
              <p className="text-muted-foreground text-[11px] leading-relaxed mb-3">
                Use AI Copilot to get contextual answers from your scan data.
              </p>
              <Link
                href="/dashboard"
                className="flex items-center gap-1.5 text-primary text-[11px] font-bold hover:gap-2 transition-all"
              >
                Open Dashboard
                <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}

// ─── 404 ─────────────────────────────────────────────────────────────────────

function NotFoundPage({ slug }: { slug: string }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen px-6 text-center">
      <div
        className="w-16 h-16 rounded-2xl flex items-center justify-center mb-6"
        style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.2)" }}
      >
        <FileText className="w-8 h-8 text-primary/50" />
      </div>
      <h1 className="text-2xl font-black text-foreground font-outfit mb-3">
        Article not found
      </h1>
      <p className="text-muted-foreground mb-6 max-w-sm">
        The documentation article &quot;{slug}&quot; does not exist. It may have been moved or renamed.
      </p>
      <Link
        href="/docs"
        className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold transition-all"
        style={{
          background: "rgba(0,255,136,0.08)",
          border: "1px solid rgba(0,255,136,0.2)",
          color: "#00FF88",
        }}
      >
        <ArrowRight className="w-4 h-4 rotate-180" />
        Back to Documentation
      </Link>

      {/* Suggest popular articles */}
      <div className="mt-10 max-w-md w-full">
        <p className="text-muted-foreground text-xs uppercase tracking-widest font-bold mb-4">
          Popular articles
        </p>
        <div className="space-y-2">
          {allArticles.slice(0, 5).map(a => (
            <Link
              key={a.slug}
              href={`/docs/${a.slug}`}
              className="flex items-center justify-between px-4 py-2.5 rounded-lg transition-colors text-sm text-muted-foreground hover:text-foreground hover:bg-[rgba(0,255,136,0.04)]"
              style={{ border: "1px solid rgba(0,255,136,0.06)" }}
            >
              {a.title}
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
