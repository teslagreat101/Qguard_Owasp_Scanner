"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Copy,
  Check,
  Info,
  AlertTriangle,
  Lightbulb,
  Image as ImageIcon,
  CheckCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { DocBlock } from "@/lib/docs-content";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-widest transition-all duration-200"
      style={{
        background: copied ? "rgba(0,255,136,0.15)" : "rgba(255,255,255,0.06)",
        color: copied ? "#00FF88" : "#6B7F77",
        border: copied ? "1px solid rgba(0,255,136,0.3)" : "1px solid rgba(255,255,255,0.08)",
      }}
    >
      {copied ? (
        <>
          <Check className="w-3 h-3" /> Copied
        </>
      ) : (
        <>
          <Copy className="w-3 h-3" /> Copy
        </>
      )}
    </button>
  );
}

interface DocsContentRendererProps {
  blocks: DocBlock[];
  className?: string;
}

export function DocsContentRenderer({ blocks, className }: DocsContentRendererProps) {
  return (
    <div className={cn("space-y-5", className)}>
      {blocks.map((block, i) => (
        <BlockRenderer key={i} block={block} />
      ))}
    </div>
  );
}

function BlockRenderer({ block }: { block: DocBlock }) {
  switch (block.type) {
    case "paragraph":
      return (
        <p className="text-muted-foreground leading-relaxed text-[15px]">
          {block.content}
        </p>
      );

    case "heading2":
      return (
        <div className="pt-4 pb-1">
          <h2
            id={block.id}
            className="text-xl font-bold text-white font-outfit tracking-tight scroll-mt-20"
          >
            {block.content}
          </h2>
          <div
            className="mt-2 h-px w-full"
            style={{ background: "linear-gradient(to right, rgba(0,255,136,0.2), transparent)" }}
          />
        </div>
      );

    case "heading3":
      return (
        <h3
          id={block.id}
          className="text-base font-semibold text-white scroll-mt-20 pt-2"
        >
          {block.content}
        </h3>
      );

    case "heading4":
      return (
        <h4
          id={block.id}
          className="text-sm font-semibold text-muted-foreground uppercase tracking-wider scroll-mt-20"
        >
          {block.content}
        </h4>
      );

    case "code":
      return (
        <div
          className="rounded-xl overflow-hidden"
          style={{ border: "1px solid rgba(0,255,136,0.12)" }}
        >
          {/* Code header */}
          <div
            className="flex items-center justify-between px-4 py-2.5"
            style={{ background: "rgba(0,255,136,0.04)", borderBottom: "1px solid rgba(0,255,136,0.08)" }}
          >
            <div className="flex items-center gap-2">
              {block.filename && (
                <span className="text-muted-foreground text-xs font-jetbrains-mono">
                  {block.filename}
                </span>
              )}
              {block.language && (
                <span
                  className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                  style={{ background: "rgba(0,255,136,0.08)", color: "#00FF88" }}
                >
                  {block.language}
                </span>
              )}
            </div>
            <CopyButton text={block.content} />
          </div>
          {/* Code body */}
          <pre
            className="p-4 overflow-x-auto text-sm leading-relaxed"
            style={{ background: "#0A0D0B", color: "#A5B3AD", fontFamily: "var(--font-jetbrains-mono), monospace" }}
          >
            <code>{block.content}</code>
          </pre>
        </div>
      );

    case "note":
      return (
        <CalloutBlock
          type="note"
          title={block.title}
          content={block.content}
          icon={<Info className="w-4 h-4 text-primary" />}
          borderColor="rgba(0,255,136,0.4)"
          bgColor="rgba(0,255,136,0.04)"
          titleColor="#00FF88"
        />
      );

    case "warning":
      return (
        <CalloutBlock
          type="warning"
          title={block.title}
          content={block.content}
          icon={<AlertTriangle className="w-4 h-4 text-orange-400" />}
          borderColor="rgba(251,146,60,0.5)"
          bgColor="rgba(251,146,60,0.04)"
          titleColor="rgb(251,146,60)"
        />
      );

    case "tip":
      return (
        <CalloutBlock
          type="tip"
          title={block.title}
          content={block.content}
          icon={<Lightbulb className="w-4 h-4 text-yellow-400" />}
          borderColor="rgba(250,204,21,0.4)"
          bgColor="rgba(250,204,21,0.03)"
          titleColor="rgb(250,204,21)"
        />
      );

    case "step":
      return (
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.3 }}
          className="flex gap-4 p-4 rounded-xl"
          style={{ background: "rgba(0,255,136,0.02)", border: "1px solid rgba(0,255,136,0.08)" }}
        >
          <div
            className="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-black font-mono"
            style={{
              background: "rgba(0,255,136,0.1)",
              border: "1px solid rgba(0,255,136,0.25)",
              color: "#00FF88",
              boxShadow: "0 0 10px rgba(0,255,136,0.1)",
            }}
          >
            {block.number}
          </div>
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-white text-sm mb-1">{block.title}</p>
            <p className="text-muted-foreground text-sm leading-relaxed">{block.content}</p>
          </div>
        </motion.div>
      );

    case "list":
      return (
        <ul className="space-y-2 pl-1">
          {block.items.map((item, i) => (
            <li key={i} className="flex items-start gap-3 text-muted-foreground text-sm leading-relaxed">
              <span
                className="flex-shrink-0 w-1.5 h-1.5 rounded-full mt-2"
                style={{ background: "#00FF88", boxShadow: "0 0 5px rgba(0,255,136,0.5)" }}
              />
              {item}
            </li>
          ))}
        </ul>
      );

    case "ordered-list":
      return (
        <ol className="space-y-2 pl-1">
          {block.items.map((item, i) => (
            <li key={i} className="flex items-start gap-3 text-muted-foreground text-sm leading-relaxed">
              <span
                className="flex-shrink-0 w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold font-mono mt-0.5"
                style={{
                  background: "rgba(0,255,136,0.08)",
                  color: "#00FF88",
                  border: "1px solid rgba(0,255,136,0.2)",
                }}
              >
                {i + 1}
              </span>
              {item}
            </li>
          ))}
        </ol>
      );

    case "table":
      return (
        <div className="overflow-x-auto rounded-xl" style={{ border: "1px solid rgba(0,255,136,0.1)" }}>
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: "rgba(0,255,136,0.05)", borderBottom: "1px solid rgba(0,255,136,0.1)" }}>
                {block.headers.map((h, i) => (
                  <th
                    key={i}
                    className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-widest text-primary"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, ri) => (
                <tr
                  key={ri}
                  className="transition-colors"
                  style={{
                    borderBottom: ri < block.rows.length - 1 ? "1px solid rgba(0,255,136,0.06)" : undefined,
                  }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLTableRowElement).style.background = "rgba(0,255,136,0.03)";
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLTableRowElement).style.background = "transparent";
                  }}
                >
                  {row.map((cell, ci) => (
                    <td
                      key={ci}
                      className={cn(
                        "px-4 py-3",
                        ci === 0
                          ? "text-primary font-medium font-mono text-xs"
                          : "text-muted-foreground"
                      )}
                    >
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );

    case "image-placeholder":
      return (
        <div
          className="rounded-xl flex flex-col items-center justify-center py-12 px-6 text-center"
          style={{
            background: "rgba(0,255,136,0.02)",
            border: "1px dashed rgba(0,255,136,0.2)",
          }}
        >
          <div
            className="w-12 h-12 rounded-xl flex items-center justify-center mb-3"
            style={{ background: "rgba(0,255,136,0.06)", border: "1px solid rgba(0,255,136,0.15)" }}
          >
            <ImageIcon className="w-6 h-6 text-primary/50" />
          </div>
          {block.label && (
            <p
              className="text-[10px] font-bold uppercase tracking-widest mb-1"
              style={{ color: "#00FF88", opacity: 0.6 }}
            >
              {block.label}
            </p>
          )}
          <p className="text-muted-foreground text-sm">{block.caption}</p>
        </div>
      );

    case "image":
      return (
        <div className="space-y-3">
          <div className="rounded-xl overflow-hidden border border-white/10 group bg-card/20">
            <img
              src={block.src}
              alt={block.alt || block.caption}
              className="w-full h-auto object-cover transition-transform duration-500 group-hover:scale-[1.02]"
            />
          </div>
          <div className="flex flex-col items-center text-center">
            {block.label && (
              <span className="text-[10px] font-bold uppercase tracking-widest text-primary/60 mb-1">
                {block.label}
              </span>
            )}
            <p className="text-xs text-muted-foreground italic font-medium">{block.caption}</p>
          </div>
        </div>
      );

    case "divider":
      return (
        <div
          className="h-px w-full my-2"
          style={{ background: "linear-gradient(to right, transparent, rgba(0,255,136,0.2), transparent)" }}
        />
      );

    case "badge-row":
      return (
        <div className="flex flex-wrap gap-2">
          {block.items.map((item, i) => (
            <span
              key={i}
              className="px-3 py-1 rounded-full text-xs font-bold"
              style={{
                background:
                  item.color === "green"
                    ? "rgba(0,255,136,0.1)"
                    : item.color === "red"
                    ? "rgba(239,68,68,0.1)"
                    : item.color === "orange"
                    ? "rgba(251,146,60,0.1)"
                    : item.color === "blue"
                    ? "rgba(96,165,250,0.1)"
                    : "rgba(255,255,255,0.06)",
                color:
                  item.color === "green"
                    ? "#00FF88"
                    : item.color === "red"
                    ? "#f87171"
                    : item.color === "orange"
                    ? "#fb923c"
                    : item.color === "blue"
                    ? "#60a5fa"
                    : "#A5B3AD",
                border: `1px solid ${
                  item.color === "green"
                    ? "rgba(0,255,136,0.25)"
                    : item.color === "red"
                    ? "rgba(239,68,68,0.25)"
                    : item.color === "orange"
                    ? "rgba(251,146,60,0.25)"
                    : item.color === "blue"
                    ? "rgba(96,165,250,0.25)"
                    : "rgba(255,255,255,0.1)"
                }`,
              }}
            >
              {item.label}
            </span>
          ))}
        </div>
      );

    default:
      return null;
  }
}

// ─── Callout Helper Component ──────────────────────────────────────────────

interface CalloutBlockProps {
  type: "note" | "warning" | "tip";
  title?: string;
  content: string;
  icon: React.ReactNode;
  borderColor: string;
  bgColor: string;
  titleColor: string;
}

function CalloutBlock({ type, title, content, icon, borderColor, bgColor, titleColor }: CalloutBlockProps) {
  const defaultTitles = { note: "Note", warning: "Warning", tip: "Tip" };

  return (
    <div
      className="rounded-xl p-4 flex gap-3"
      style={{
        background: bgColor,
        border: `1px solid ${borderColor}`,
        borderLeftWidth: "3px",
      }}
    >
      <div className="flex-shrink-0 mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold mb-1" style={{ color: titleColor }}>
          {title ?? defaultTitles[type]}
        </p>
        <p className="text-muted-foreground text-sm leading-relaxed">{content}</p>
      </div>
    </div>
  );
}
