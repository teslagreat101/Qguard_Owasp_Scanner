"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Rocket,
  Settings,
  Scan,
  Bot,
  LayoutDashboard,
  GraduationCap,
  BookOpen,
  ChevronDown,
  ChevronRight,
  Search,
  X,
  Menu,
  FileText,
  ArrowLeft,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { docsSections, searchArticles, type DocArticle } from "@/lib/docs-content";

const SECTION_ICONS: Record<string, React.ElementType> = {
  rocket: Rocket,
  settings: Settings,
  scan: Scan,
  bot: Bot,
  layout: LayoutDashboard,
  "graduation-cap": GraduationCap,
  book: BookOpen,
};

interface DocsSidebarProps {
  className?: string;
}

export function DocsSidebar({ className }: DocsSidebarProps) {
  const pathname = usePathname();
  const currentSlug = pathname.replace("/docs/", "").replace("/docs", "");

  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<DocArticle[]>([]);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Auto-open section containing active article
  useEffect(() => {
    const activeSection = docsSections.find(s =>
      s.articles.some(a => a.slug === currentSlug)
    );
    if (activeSection) {
      setOpenSections(prev => ({ ...prev, [activeSection.id]: true }));
    }
  }, [currentSlug]);

  // Search logic
  useEffect(() => {
    if (searchQuery.trim()) {
      setSearchResults(searchArticles(searchQuery));
    } else {
      setSearchResults([]);
    }
  }, [searchQuery]);

  const toggleSection = (sectionId: string) => {
    setOpenSections(prev => ({ ...prev, [sectionId]: !prev[sectionId] }));
  };

  const handleArticleClick = () => {
    setIsMobileOpen(false);
    setSearchQuery("");
  };

  const SidebarContent = () => (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 pt-6 pb-4 border-b border-[rgba(0,255,136,0.08)]">
        <Link
          href="/"
          className="flex items-center gap-2 mb-5 group"
          onClick={handleArticleClick}
        >
          <ArrowLeft className="w-3.5 h-3.5 text-muted-foreground group-hover:text-primary transition-colors" />
          <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground group-hover:text-primary transition-colors">
            Back to App
          </span>
        </Link>

        <div className="flex items-center gap-2.5 mb-5">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.2)" }}
          >
            <FileText className="w-4 h-4 text-primary" />
          </div>
          <div>
            <p className="text-white font-bold text-sm font-outfit">Documentation</p>
            <p className="text-muted-foreground text-[10px] tracking-wider">Quantara Platform</p>
          </div>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Search docs..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-8 py-2 rounded-lg text-sm text-white placeholder-[#6B7F77] bg-[rgba(0,255,136,0.04)] border border-[rgba(0,255,136,0.12)] focus:outline-none focus:border-[rgba(0,255,136,0.3)] focus:bg-[rgba(0,255,136,0.06)] transition-all"
          />
          {searchQuery && (
            <button
              type="button"
              aria-label="Clear search"
              onClick={() => setSearchQuery("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-white transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Search Results */}
      <AnimatePresence>
        {searchQuery && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="border-b border-[rgba(0,255,136,0.08)] overflow-hidden"
          >
            <div className="px-4 py-3">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">
                {searchResults.length} result{searchResults.length !== 1 ? "s" : ""}
              </p>
              {searchResults.length === 0 ? (
                <p className="text-muted-foreground text-xs py-2">No results found</p>
              ) : (
                <div className="space-y-1">
                  {searchResults.slice(0, 8).map(article => (
                    <Link
                      key={article.slug}
                      href={`/docs/${article.slug}`}
                      onClick={handleArticleClick}
                      className={cn(
                        "block px-3 py-2 rounded-lg text-xs transition-all duration-200",
                        currentSlug === article.slug
                          ? "bg-[rgba(0,255,136,0.1)] text-primary"
                          : "text-muted-foreground hover:bg-[rgba(0,255,136,0.05)] hover:text-white"
                      )}
                    >
                      <span className="font-medium">{article.title}</span>
                      <span className="text-muted-foreground ml-1.5 text-[10px]">
                        {article.category}
                      </span>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-1 custom-scrollbar">
        {docsSections.map(section => {
          const Icon = SECTION_ICONS[section.icon] || BookOpen;
          const isOpen = openSections[section.id] ?? false;
          const hasActive = section.articles.some(a => a.slug === currentSlug);

          return (
            <div key={section.id}>
              {/* Section Header */}
              <button
                type="button"
                aria-label={`${openSections[section.id] ? "Collapse" : "Expand"} ${section.title}`}
                onClick={() => toggleSection(section.id)}
                className={cn(
                  "w-full flex items-center justify-between px-3 py-2.5 rounded-lg transition-all duration-200 group",
                  hasActive
                    ? "bg-[rgba(0,255,136,0.07)] text-white"
                    : "text-muted-foreground hover:bg-[rgba(0,255,136,0.04)] hover:text-white"
                )}
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={cn(
                      "w-4 h-4 flex-shrink-0 transition-colors",
                      hasActive ? "text-primary" : "text-muted-foreground group-hover:text-primary"
                    )}
                  />
                  <span className="text-xs font-semibold tracking-wide">{section.title}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {section.articles.length}
                  </span>
                  {isOpen ? (
                    <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                  )}
                </div>
              </button>

              {/* Articles List */}
              <AnimatePresence initial={false}>
                {isOpen && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.2, ease: "easeInOut" }}
                    className="overflow-hidden ml-2"
                  >
                    <div className="pl-4 border-l border-[rgba(0,255,136,0.08)] mt-1 mb-2 space-y-0.5">
                      {section.articles.map(article => {
                        const isActive = article.slug === currentSlug;
                        return (
                          <Link
                            key={article.slug}
                            href={`/docs/${article.slug}`}
                            onClick={handleArticleClick}
                            className={cn(
                              "block px-3 py-2 rounded-lg text-xs transition-all duration-200 relative",
                              isActive
                                ? "text-primary bg-[rgba(0,255,136,0.08)] font-medium"
                                : "text-muted-foreground hover:text-white hover:bg-[rgba(255,255,255,0.03)]"
                            )}
                          >
                            {isActive && (
                              <span
                                className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 rounded-r"
                                style={{ background: "#00FF88", boxShadow: "0 0 6px rgba(0,255,136,0.6)" }}
                              />
                            )}
                            {article.title}
                          </Link>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-[rgba(0,255,136,0.08)]">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-primary animate-pulse shadow-[0_0_6px_#00FF88]" />
          <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            Docs v3.0
          </span>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Toggle Button */}
      <button
        type="button"
        aria-label="Open documentation menu"
        onClick={() => setIsMobileOpen(true)}
        className="fixed top-4 left-4 z-50 lg:hidden w-10 h-10 rounded-xl flex items-center justify-center"
        style={{ background: "rgba(0,255,136,0.08)", border: "1px solid rgba(0,255,136,0.2)" }}
      >
        <Menu className="w-5 h-5 text-primary" />
      </button>

      {/* Mobile Overlay */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
            onClick={() => setIsMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.aside
            initial={{ x: -280 }}
            animate={{ x: 0 }}
            exit={{ x: -280 }}
            transition={{ type: "spring", damping: 30, stiffness: 300 }}
            className="fixed left-0 top-0 bottom-0 z-50 w-72 lg:hidden overflow-hidden"
            style={{
              background: "#0B0F0C",
              borderRight: "1px solid rgba(0,255,136,0.1)",
            }}
          >
            <button
              type="button"
              aria-label="Close documentation menu"
              onClick={() => setIsMobileOpen(false)}
              className="absolute top-4 right-4 z-10 w-8 h-8 rounded-lg flex items-center justify-center text-muted-foreground hover:text-white transition-colors"
              style={{ background: "rgba(255,255,255,0.05)" }}
            >
              <X className="w-4 h-4" />
            </button>
            <SidebarContent />
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <aside
        className={cn(
          "hidden lg:flex flex-col w-64 xl:w-72 flex-shrink-0 h-screen sticky top-0 overflow-hidden",
          className
        )}
        style={{
          background: "#0B0F0C",
          borderRight: "1px solid rgba(0,255,136,0.08)",
        }}
      >
        <SidebarContent />
      </aside>

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(0, 255, 136, 0.15);
          border-radius: 2px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: rgba(0, 255, 136, 0.3);
        }
      `}</style>
    </>
  );
}
