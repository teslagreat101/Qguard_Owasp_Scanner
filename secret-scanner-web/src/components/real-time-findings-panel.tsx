"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import {
  AlertTriangle,
  Shield,
  Key,
  Database,
  FileCode,
  Search,
  Terminal,
  ChevronDown,
  ChevronUp,
  X,
  Eye,
  EyeOff,
  Lock,
} from "lucide-react";
import type { Finding } from "@/hooks/use-scanner";

interface RealTimeFindingsPanelProps {
  findings: Finding[];
  isScanning: boolean;
  scanStatus: {
    progress: number;
    active_module: string | null;
    modules_completed: number;
    modules_total: number;
  } | null;
  onClear?: () => void;
}

function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-500/15 text-red-400 border-red-500/30";
    case "high":
      return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/15 text-yellow-400 border-yellow-500/30";
    case "low":
      return "bg-[rgba(0,255,136,0.1)] text-primary border-[rgba(0,255,136,0.2)]";
    default:
      return "bg-muted/10 text-muted-foreground border-border/20";
  }
}

function getSeverityIcon(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return <AlertTriangle className="h-4 w-4 text-red-400" />;
    case "high":
      return <Shield className="h-4 w-4 text-orange-400" />;
    case "medium":
      return <Key className="h-4 w-4 text-yellow-400" />;
    case "low":
      return <Database className="h-4 w-4 text-primary" />;
    default:
      return <FileCode className="h-4 w-4 text-muted-foreground" />;
  }
}

function getCategoryIcon(category: string) {
  if (category.includes("Injection")) return <Terminal className="h-4 w-4" />;
  if (category.includes("Misconfiguration")) return <Shield className="h-4 w-4" />;
  if (category.includes("Cryptographic")) return <Key className="h-4 w-4" />;
  if (category.includes("Access")) return <AlertTriangle className="h-4 w-4" />;
  return <FileCode className="h-4 w-4" />;
}

export function RealTimeFindingsPanel({
  findings,
  isScanning,
  scanStatus,
  onClear,
}: RealTimeFindingsPanelProps) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<string>("all");

  const toggleSecretReveal = (findingId: string) => {
    setRevealedSecrets((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(findingId)) {
        newSet.delete(findingId);
      } else {
        newSet.add(findingId);
      }
      return newSet;
    });
  };

  const severityCount = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };

  const filteredFindings =
    filter === "all"
      ? findings
      : findings.filter((f) => f.severity === filter);

  const latestFindings = filteredFindings.slice(0, 100);

  return (
    <Card className="bg-card border-primary/10 h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-white flex items-center gap-2">
              <Search className="h-5 w-5 text-primary" />
              Live Findings Feed
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              Real-time security findings as they are detected
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {isScanning && (
              <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[rgba(0,255,136,0.1)] border border-[rgba(0,255,136,0.2)]">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-xs text-primary font-medium">
                  {scanStatus?.active_module
                    ? `Scanning: ${scanStatus.active_module}`
                    : "Scanning..."}
                </span>
              </div>
            )}
            {findings.length > 0 && onClear && (
              <Button
                variant="ghost"
                size="sm"
                onClick={onClear}
                className="text-muted-foreground hover:text-red-400"
              >
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>

        {/* Severity Counters */}
        <div className="flex flex-wrap gap-2 mt-4">
          {[
            { key: "all", label: "All", count: findings.length, color: "text-white" },
            { key: "critical", label: "Critical", count: severityCount.critical, color: "text-red-400" },
            { key: "high", label: "High", count: severityCount.high, color: "text-orange-400" },
            { key: "medium", label: "Medium", count: severityCount.medium, color: "text-yellow-400" },
            { key: "low", label: "Low", count: severityCount.low, color: "text-primary" },
          ].map((item) => (
            <button
              key={item.key}
              onClick={() => setFilter(item.key)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${filter === item.key
                  ? "bg-[rgba(0,255,136,0.15)] border border-[rgba(0,255,136,0.3)]"
                  : "bg-[rgba(0,255,136,0.04)] border border-[rgba(0,255,136,0.08)] hover:border-[rgba(0,255,136,0.2)]"
                }`}
            >
              <span className={item.color}>{item.label}</span>
              <span className="text-muted-foreground">({item.count})</span>
            </button>
          ))}
        </div>
      </CardHeader>

      <CardContent className="p-0">
        <ScrollArea className="h-[280px] px-4">
          {latestFindings.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
              <Search className="h-12 w-12 mb-4 opacity-30" />
              <p className="text-sm">
                {isScanning
                  ? "Waiting for findings..."
                  : "No findings yet. Start a scan to detect security issues."}
              </p>
            </div>
          ) : (
            <div className="space-y-2 py-2">
              <AnimatePresence>
                {latestFindings.map((finding, index) => (
                  <motion.div
                    key={finding.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ delay: index * 0.02 }}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${expandedFinding === finding.id
                        ? "bg-[rgba(0,255,136,0.08)] border-[rgba(0,255,136,0.25)]"
                        : "bg-[rgba(0,255,136,0.02)] border-[rgba(0,255,136,0.08)] hover:border-[rgba(0,255,136,0.2)]"
                      }`}
                    onClick={() =>
                      setExpandedFinding(
                        expandedFinding === finding.id ? null : finding.id
                      )
                    }
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {getSeverityIcon(finding.severity)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-white text-sm truncate">
                            {finding.title}
                          </span>
                          <Badge
                            className={`text-xs ${getSeverityColor(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                          <span className="font-mono text-primary">
                            {finding.file}:{finding.line_number}
                          </span>
                          <span>•</span>
                          <span>{finding.module_name}</span>
                          <span>•</span>
                          <span>{finding.cwe}</span>
                        </div>

                        {expandedFinding === finding.id && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-3 pt-3 border-t border-primary/10"
                          >
                            <p className="text-sm text-muted-foreground mb-2">
                              {finding.description}
                            </p>

                            {/* Credential Viewer */}
                            {finding.matched_content && (
                              <div className="bg-[rgba(0,0,0,0.3)] rounded-lg p-3 mb-3 border border-[rgba(255,100,100,0.2)]">
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center gap-2">
                                    <Lock className="h-4 w-4 text-red-400" />
                                    <span className="text-xs font-medium text-red-400 uppercase tracking-wider">
                                      Exposed Secret Detected
                                    </span>
                                  </div>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      toggleSecretReveal(finding.id);
                                    }}
                                    className="h-7 px-2 text-primary hover:text-white hover:bg-[rgba(0,255,136,0.2)]"
                                  >
                                    {revealedSecrets.has(finding.id) ? (
                                      <>
                                        <EyeOff className="h-3.5 w-3.5 mr-1" />
                                        <span className="text-xs">Hide</span>
                                      </>
                                    ) : (
                                      <>
                                        <Eye className="h-3.5 w-3.5 mr-1" />
                                        <span className="text-xs">View Secret</span>
                                      </>
                                    )}
                                  </Button>
                                </div>

                                {revealedSecrets.has(finding.id) ? (
                                  <>
                                    <div className="bg-red-500/10 border border-red-500/20 rounded p-2 mb-2">
                                      <p className="text-xs text-red-400 font-mono break-all">
                                        {finding.matched_content}
                                      </p>
                                    </div>
                                    <p className="text-[10px] text-red-400/80">
                                      <AlertTriangle className="h-3 w-3 inline mr-1" />
                                      Warning: This is sensitive data. Handle with extreme caution.
                                    </p>
                                  </>
                                ) : (
                                  <>
                                    <div className="flex items-center gap-1">
                                      <span className="text-xs text-muted-foreground font-mono">
                                        {finding.matched_content.slice(0, 20).replace(/./g, "•")}
                                        {finding.matched_content.length > 20 ? "..." : ""}
                                      </span>
                                      <span className="text-xs text-muted-foreground ml-2">
                                        ({finding.matched_content.length} chars)
                                      </span>
                                    </div>
                                    <p className="text-[10px] text-muted-foreground mt-2">
                                      Click "View Secret" to reveal the matched content for validation.
                                    </p>
                                  </>
                                )}
                              </div>
                            )}

                            <div className="flex items-center gap-2 flex-wrap">
                              {finding.tags.map((tag) => (
                                <Badge
                                  key={tag}
                                  variant="outline"
                                  className="text-[10px] border-[rgba(0,255,136,0.15)] text-muted-foreground"
                                >
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                            {finding.remediation && (
                              <div className="mt-2 p-2 bg-[rgba(0,255,136,0.04)] rounded-lg">
                                <p className="text-xs text-muted-foreground font-medium">
                                  Remediation
                                </p>
                                <p className="text-xs text-muted-foreground mt-1">
                                  {finding.remediation}
                                </p>
                              </div>
                            )}
                          </motion.div>
                        )}
                      </div>
                      <div className="text-muted-foreground">
                        {expandedFinding === finding.id ? (
                          <ChevronUp className="h-4 w-4" />
                        ) : (
                          <ChevronDown className="h-4 w-4" />
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
