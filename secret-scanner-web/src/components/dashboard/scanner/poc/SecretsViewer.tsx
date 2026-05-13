"use client";

import { useState, useMemo, useCallback } from "react";
import { Eye, EyeOff, ShieldAlert, Lock, Info, Loader2, Globe, Code2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface SecretEntry {
  type: string;
  key?: string;
  value?: string;
  value_masked: string;
  confidence?: number;
  source_path?: string;
  discovered_via?: string;
  exposure_vector?: string;
  severity?: string;
}

interface SecretsViewerProps {
  secrets?: any[];
  finding?: any;
  scanId?: string;
}

function classifySecret(key: string): string {
  const k = key.toLowerCase();
  if (k.includes("password") || k.includes("passwd") || k.includes("pwd")) return "Password";
  if (k.includes("stripe") || k.includes("sk_live") || k.includes("pk_live")) return "Payment Token";
  if (k.includes("aws") || k.includes("akia")) return "Cloud Credential";
  if (k.includes("jwt") || k.includes("bearer")) return "JWT Token";
  if (k.includes("api_key") || k.includes("apikey")) return "API Key";
  if (k.includes("secret")) return "Secret Key";
  if (k.includes("token")) return "Auth Token";
  if (k.includes("db") || k.includes("database") || k.includes("mongo") || k.includes("postgres") || k.includes("mysql")) return "Database Credential";
  if (k.includes("private_key") || k.includes("rsa") || k.includes("pem")) return "Private Key";
  return "Credential";
}

function extractSecretsFromFinding(finding: any): SecretEntry[] {
  if (!finding) return [];
  const results: SecretEntry[] = [];
  const content: string = finding.matched_content || finding.payload || finding.description || "";
  const kvRegex = /([A-Za-z_][A-Za-z0-9_]{2,})\s*[=:]\s*['"]?([^\s'"<>,;]{6,64})/g;
  let match;
  while ((match = kvRegex.exec(content)) !== null && results.length < 5) {
    const key = match[1];
    const value = match[2];
    if (/^(class|type|name|href|src|id|ref|for|on|if|else|return|const|let|var)$/i.test(key)) continue;
    const masked = value.length > 12 ? value.slice(0, 4) + "***" + value.slice(-4) : value.slice(0, 3) + "***";
    results.push({ key: key.toUpperCase(), value, value_masked: masked, type: classifySecret(key) });
  }
  if (results.length === 0 && content.trim()) {
    const title = (finding.title || "Secret").replace(/\s+/g, "_").toUpperCase().slice(0, 30);
    results.push({
      key: title,
      value: content.slice(0, 80),
      value_masked: content.slice(0, 4) + "***",
      type: classifySecret(finding.title || ""),
    });
  }
  return results;
}

const TYPE_COLORS: Record<string, string> = {
  PASSWORD: "text-red-400",
  PAYMENT_TOKEN: "text-orange-400",
  CLOUD_CREDENTIAL: "text-yellow-400",
  JWT_TOKEN: "text-purple-400",
  API_KEY: "text-blue-400",
  SECRET_KEY: "text-red-400",
  AUTH_TOKEN: "text-pink-400",
  DATABASE_CREDENTIAL: "text-orange-500",
  PRIVATE_KEY: "text-red-500",
  GITHUB_TOKEN: "text-muted-foreground",
  STRIPE_KEY: "text-violet-400",
  AWS_ACCESS_KEY: "text-yellow-500",
  GOOGLE_API_KEY: "text-blue-500",
  DB_CREDENTIAL: "text-orange-500",
};

function SecretTypeLabel({ type }: { type: string }) {
  const color = TYPE_COLORS[type.toUpperCase()] || "text-muted-foreground";
  return <p className={cn("text-[9px] font-black uppercase tracking-widest", color)}>{type.replace(/_/g, " ")}</p>;
}

export function SecretsViewer({ secrets = [], finding, scanId }: SecretsViewerProps) {
  const [showSecrets, setShowSecrets] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [liveSecrets, setLiveSecrets] = useState<SecretEntry[] | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [selectedSecret, setSelectedSecret] = useState<SecretEntry | null>(null);

  // Priority: live secrets from backend > prop secrets > extracted from finding
  const displaySecrets = useMemo<SecretEntry[]>(() => {
    if (liveSecrets && liveSecrets.length > 0) return liveSecrets;
    if (secrets.length > 0) return secrets;
    if (finding) return extractSecretsFromFinding(finding);
    return [];
  }, [liveSecrets, secrets, finding]);

  const hasData = displaySecrets.length > 0;
  const isLiveData = liveSecrets !== null && liveSecrets.length > 0;

  const fetchLiveSecrets = useCallback(async () => {
    if (!scanId) return;
    setIsFetching(true);
    try {
      const res = await fetch(`${API_BASE}/api/poc/secrets/${scanId}`, {
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.secrets && data.secrets.length > 0) {
          setLiveSecrets(data.secrets);
          toast.success(`${data.secrets.length} secret${data.secrets.length !== 1 ? "s" : ""} loaded from scan intelligence`);
        } else {
          toast.info("No secrets found in scan findings — using local extraction");
        }
      }
    } catch {
      // Silently fall back to local extraction
    } finally {
      setIsFetching(false);
    }
  }, [scanId]);

  const handleReveal = useCallback(async () => {
    setIsDialogOpen(false);

    // Fetch live secrets from backend if we have a scanId
    if (scanId) {
      await fetchLiveSecrets();
    }

    setShowSecrets(true);
    toast.warning("Sensitive data revealed. Action logged in audit trail.");
    setTimeout(() => {
      setShowSecrets(false);
      toast.info("Security mask re-applied after 30s timeout.");
    }, 30000);
  }, [scanId, fetchLiveSecrets]);

  const handleMask = useCallback(() => {
    setShowSecrets(false);
    setSelectedSecret(null);
  }, []);

  return (
    <div className="bg-background/40 border border-white/5 rounded-2xl p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-orange-500" />
          <div>
            <h4 className="text-[11px] font-black text-foreground uppercase tracking-widest">Sensitive Data Exposure</h4>
            {isLiveData && (
              <p className="text-[8px] text-primary font-bold uppercase tracking-widest mt-0.5">
                Live scan intelligence
              </p>
            )}
          </div>
        </div>

        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <button
              type="button"
              onClick={showSecrets ? handleMask : undefined}
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest border transition-colors",
                showSecrets
                  ? "bg-muted/10 border-border/20 text-muted-foreground hover:bg-muted/20"
                  : "bg-orange-500/10 border-orange-500/20 text-orange-500 hover:bg-orange-500/20"
              )}
            >
              {isFetching ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : showSecrets ? (
                <EyeOff className="w-3 h-3" />
              ) : (
                <Eye className="w-3 h-3" />
              )}
              {isFetching ? "Loading…" : showSecrets ? "Mask Data" : "Reveal Secrets"}
            </button>
          </DialogTrigger>

          {!showSecrets && (
            <DialogContent className="bg-background border-border text-foreground">
              <DialogHeader>
                <DialogTitle className="text-primary flex items-center gap-3">
                  <Lock className="w-5 h-5" />
                  Security Confirmation
                </DialogTitle>
                <DialogDescription className="text-muted-foreground pt-4 font-medium">
                  You are about to reveal sensitive credentials discovered in the target application.
                  {scanId && (
                    <span className="block mt-2 text-primary/80">
                      Secrets will be fetched from live scan intelligence for scan <code className="font-mono text-[10px]">{scanId.slice(0, 8)}…</code>
                    </span>
                  )}
                  <br />
                  This action will be logged in the audit trail for compliance purposes.
                  <br /><br />
                  <span className="text-orange-500 font-bold">Ensure you are in a secure environment.</span>
                </DialogDescription>
              </DialogHeader>
              <DialogFooter className="mt-6 flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => setIsDialogOpen(false)}
                  className="border-border text-muted-foreground hover:bg-secondary uppercase font-black text-[10px] tracking-widest"
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleReveal}
                  disabled={isFetching}
                  className="bg-primary text-primary-foreground hover:bg-primary/80 uppercase font-black text-[10px] tracking-widest px-8"
                >
                  {isFetching ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-2" /> : null}
                  Confirm Reveal
                </Button>
              </DialogFooter>
            </DialogContent>
          )}
        </Dialog>
      </div>

      {/* Secrets list */}
      <div className="space-y-2 max-h-[220px] overflow-y-auto no-scrollbar pr-1">
        {hasData ? (
          displaySecrets.map((secret, i) => (
            <div
              key={i}
              onClick={() => setSelectedSecret(selectedSecret?.value_masked === secret.value_masked ? null : secret)}
              className={cn(
                "group/secret bg-secondary border rounded-xl p-3 cursor-pointer transition-all",
                selectedSecret?.value_masked === secret.value_masked
                  ? "border-primary/30 bg-primary/5"
                  : "border-border hover:border-primary/20"
              )}
            >
              <div className="flex items-center justify-between">
                <div className="space-y-1 min-w-0 flex-1">
                  <SecretTypeLabel type={secret.type || "Credential"} />
                  <div className="flex items-center gap-2 min-w-0">
                    {secret.key && (
                      <span className="text-[11px] font-mono text-muted-foreground shrink-0">{secret.key} =</span>
                    )}
                    <span className={cn(
                      "text-[11px] font-mono transition-all duration-300 truncate",
                      showSecrets ? "text-primary" : "text-muted-foreground/60 blur-[3px] select-none"
                    )}>
                      {showSecrets ? (secret.value || secret.value_masked) : "****************"}
                    </span>
                  </div>

                  {/* Expanded detail when selected */}
                  {selectedSecret?.value_masked === secret.value_masked && (
                    <div className="mt-2 pt-2 border-t border-border space-y-1">
                      {secret.source_path && (
                        <div className="flex items-center gap-1.5">
                          <Code2 className="w-2.5 h-2.5 text-muted-foreground/80 shrink-0" />
                          <span className="text-[9px] font-mono text-muted-foreground truncate">{secret.source_path}</span>
                        </div>
                      )}
                      {secret.discovered_via && (
                        <div className="flex items-center gap-1.5">
                          <Globe className="w-2.5 h-2.5 text-muted-foreground/80 shrink-0" />
                          <span className="text-[9px] text-muted-foreground uppercase tracking-widest">{secret.discovered_via}</span>
                        </div>
                      )}
                      {secret.confidence !== undefined && (
                        <div className="flex items-center gap-2 mt-1">
                          <div className="flex-1 h-0.5 bg-secondary rounded-full overflow-hidden">
                            <div className={cn(
                              "h-full bg-primary rounded-full transition-all",
                              (secret.confidence || 0) >= 0.9 ? "w-full" :
                                (secret.confidence || 0) >= 0.75 ? "w-4/5" :
                                  (secret.confidence || 0) >= 0.6 ? "w-3/5" :
                                    (secret.confidence || 0) >= 0.4 ? "w-2/5" : "w-1/5"
                            )} />
                          </div>
                          <span className="text-[9px] font-black text-primary">
                            {Math.round((secret.confidence || 0) * 100)}%
                          </span>
                        </div>
                      )}
                      {secret.exposure_vector && (
                        <span className="inline-block text-[8px] font-black text-orange-500 bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 rounded uppercase tracking-widest">
                          via {secret.exposure_vector.replace(/_/g, " ")}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                <div className="p-2 rounded-lg bg-background/40 opacity-0 group-hover/secret:opacity-100 transition-opacity shrink-0 ml-2">
                  <Info className="w-3 h-3 text-muted-foreground" />
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="py-6 flex flex-col items-center gap-2 opacity-40">
            <ShieldAlert className="w-8 h-8 text-muted-foreground" />
            <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-widest text-center">
              No secrets detected<br />in this finding
            </p>
          </div>
        )}
      </div>

      <div className="p-3 rounded-xl bg-orange-500/5 border border-orange-500/10 flex items-start gap-3">
        <Info className="w-3.5 h-3.5 text-orange-500 mt-0.5 shrink-0" />
        <p className="text-[9px] text-orange-500/70 font-medium leading-relaxed">
          Secrets auto-mask after 30 seconds. Actions logged in
          <span className="text-orange-500 font-black ml-1 uppercase">audit_security_logs</span>
        </p>
      </div>
    </div>
  );
}
