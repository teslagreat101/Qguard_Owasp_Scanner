"use client";

import React from "react";
import { Globe, Copy, Hash, Key, User } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface EndpointViewerProps {
  data: any;
}

export function EndpointViewer({ data }: EndpointViewerProps) {
  const endpoint = data.endpoint || data.file || data.path || "/unknown-endpoint";
  const matchedContent = data.matched_content || data.payload || "";
  const cweTag = data.cwe ? `${data.cwe}` : null;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  return (
    <div className="bg-background/40 border border-border rounded-2xl p-5 space-y-5 h-full">
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <Globe className="w-4 h-4 text-primary" />
        <h4 className="text-[11px] font-black text-foreground uppercase tracking-widest">Discovered Target Data</h4>
      </div>

      <div className="space-y-4">
        <div className="space-y-1.5 min-w-0">
          <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Endpoint / File</p>
          <div className="flex items-center gap-2 bg-secondary border border-border rounded-lg p-2.5 group/url overflow-hidden">
            <span className="text-[11px] font-mono text-muted-foreground truncate flex-1">{endpoint}</span>
            <button
              type="button"
              onClick={() => copyToClipboard(endpoint, "Endpoint")}
              className="p-1.5 rounded-md hover:bg-muted/50 text-muted-foreground hover:text-primary transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Severity</p>
            <div className="bg-primary/5 border border-primary/10 rounded-lg px-3 py-1.5">
              <span className="text-xs font-black text-primary uppercase">{data.severity || "info"}</span>
            </div>
          </div>
          <div className="space-y-1.5">
            <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">CWE / Category</p>
            <div className="bg-secondary border border-border rounded-lg px-3 py-1.5">
              <span className="text-xs font-black text-muted-foreground">{cweTag || data.category || "N/A"}</span>
            </div>
          </div>
        </div>

        {data.line_number > 0 && (
          <div className="space-y-1.5">
            <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Line Number</p>
            <div className="bg-secondary border border-border rounded-lg px-3 py-2 text-xs font-mono text-muted-foreground">
              Line {data.line_number}
            </div>
          </div>
        )}

        <div className="space-y-1.5">
          <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Module / OWASP</p>
          <div className="bg-background/40 border border-border rounded-xl p-3 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <User className="w-4 h-4 text-yellow-500" />
            </div>
            <p className="text-[10px] text-muted-foreground font-medium leading-tight">
              {data.module_name || data.module || "Scanner Engine"}<br />
              <span className="text-muted-foreground/70 font-mono">{data.owasp || "OWASP Top 10"}</span>
            </p>
          </div>
        </div>

        {matchedContent && (
          <div className="space-y-1.5 pt-2">
            <p className="text-[9px] text-muted-foreground font-bold uppercase tracking-widest">Matched Evidence</p>
            <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-3 space-y-2">
              <code className="text-[11px] font-mono text-destructive break-all leading-relaxed bg-background/40 p-2 rounded block max-h-24 overflow-y-auto">
                {matchedContent.slice(0, 300)}{matchedContent.length > 300 ? "..." : ""}
              </code>
              <button
                type="button"
                onClick={() => copyToClipboard(matchedContent, "Evidence")}
                className="w-full py-2 rounded-lg bg-destructive/10 hover:bg-destructive/20 border border-destructive/20 text-[9px] font-black text-destructive uppercase tracking-widest transition-all"
              >
                Copy Evidence
              </button>
            </div>
          </div>
        )}
      </div>

    </div>
  );
}

