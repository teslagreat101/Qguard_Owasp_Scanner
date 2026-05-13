"use client";

import { useState } from "react";
import {
  Bot,
  Sparkles,
  MessageSquare,
  Lightbulb,
  ArrowRight,
  ShieldCheck,
  Zap,
  Code2,
  ClipboardList,
  CheckCircle2,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Loader2,
  ExternalLink,
  Copy,
  Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────

interface PocFix {
  vulnerability_type: string;
  poc_description: string;
  immediate_fix: string;
  full_fix_code: string;
  fix_language: string;
  fix_explanation: string;
  test_steps: string[];
  prevention_checklist: string[];
  cvss_score: string;
  owasp_category: string;
  references: string[];
  provider_used: string;
}

interface POCExecutionResult {
  status_code?: number;
  response_time_ms?: number;
  server?: string;
  content_type?: string;
  verification_status?: string;
  evidence_match?: boolean;
  secrets_detected?: any[];
  disclosed_headers?: string[];
  body_pretty?: string;
  error?: string;
}

interface AIAdvisorProps {
  vulnerability: any;
  pocResult?: POCExecutionResult | null;
}

// ── Provider badge ──────────────────────────────────────────────────────────

const PROVIDER_COLORS: Record<string, string> = {
  gemini: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  anthropic: "text-purple-400 bg-purple-400/10 border-purple-400/20",
  openai: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20",
  local: "text-primary bg-primary/10 border-primary/20",
  none: "text-muted-foreground bg-secondary border-border",
};

const PROVIDER_LABELS: Record<string, string> = {
  gemini: "Gemini",
  anthropic: "Claude",
  openai: "GPT",
  local: "Local Engine",
  none: "N/A",
};

function ProviderBadge({ provider }: { provider: string }) {
  const cls = PROVIDER_COLORS[provider] ?? PROVIDER_COLORS.none;
  const label = PROVIDER_LABELS[provider] ?? provider;
  return (
    <span className={cn("text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded border", cls)}>
      {label}
    </span>
  );
}

// ── Code block with copy ─────────────────────────────────────────────────────

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="relative group/code rounded-xl overflow-hidden border border-primary/10 bg-background/60">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-primary/5 border-b border-primary/10">
        <div className="flex items-center gap-1.5">
          <Code2 className="w-3 h-3 text-primary/60" />
          <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
            {language || "code"}
          </span>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 text-[9px] text-muted-foreground hover:text-primary transition-colors"
        >
          {copied ? <Check className="w-3 h-3 text-primary" /> : <Copy className="w-3 h-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {/* Code */}
      <pre className="p-3 text-[10px] text-muted-foreground w-full max-w-full overflow-x-auto whitespace-pre-wrap break-words font-mono">
        {code}
      </pre>
    </div>
  );
}

// ── Local rule-based fix generator (offline fallback) ──────────────────────

function generateLocalFix(v: any): PocFix {
  const title = (v.title || "").toLowerCase();
  const cwe = (v.cwe || "").toLowerCase();
  const owasp = v.owasp || "OWASP Top 10";

  if (title.includes("sql") || cwe.includes("89")) {
    return {
      vulnerability_type: "SQL Injection",
      poc_description: "Unsanitised user input is concatenated directly into a SQL query, allowing an attacker to manipulate query logic and extract or destroy data.",
      immediate_fix: "Replace string concatenation with parameterised queries / prepared statements immediately.",
      full_fix_code:
        `// ❌ Vulnerable
db.query(\`SELECT * FROM users WHERE id = \${userId}\`);

// ✅ Fixed — parameterised query
db.query("SELECT * FROM users WHERE id = ?", [userId]);

// Python / SQLAlchemy
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})`,
      fix_language: "javascript",
      fix_explanation: "Parameterised queries separate data from SQL syntax, making it structurally impossible for user input to be interpreted as SQL code.",
      test_steps: ["Re-run scanner after the fix", "Test with payload: ' OR 1=1 --", "Verify no unintended rows are returned"],
      prevention_checklist: ["Use an ORM with parameterised queries", "Enable WAF SQL injection ruleset", "Run SAST on every CI build", "Never expose raw SQL error messages"],
      cvss_score: "9.8", owasp_category: "A03:2021 – Injection",
      references: ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
      provider_used: "local",
    };
  }

  if (title.includes("xss") || title.includes("cross-site") || cwe.includes("79")) {
    return {
      vulnerability_type: "Cross-Site Scripting (XSS)",
      poc_description: "User-controlled data is rendered in the browser without encoding, letting attackers inject scripts that run in victims' sessions.",
      immediate_fix: "Escape all user-supplied output before inserting into HTML context.",
      full_fix_code:
        `// ❌ Vulnerable
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ✅ Fixed — React auto-escapes JSX
<div>{userInput}</div>

// Server-side escaping
const esc = (s) => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");`,
      fix_language: "jsx",
      fix_explanation: "HTML encoding prevents angle-brackets from being interpreted as markup, neutralising script injection.",
      test_steps: ["Inject <script>alert(1)</script> in all inputs", "Verify no alert appears", "Check Content-Security-Policy header is set"],
      prevention_checklist: ["Never use innerHTML with user data", "Set a strict CSP header", "Use DOMPurify for rich-text fields", "Enable HTTPOnly + Secure cookies"],
      cvss_score: "6.1", owasp_category: "A03:2021 – Injection",
      references: ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
      provider_used: "local",
    };
  }

  if (title.includes("ssrf") || cwe.includes("918")) {
    return {
      vulnerability_type: "Server-Side Request Forgery (SSRF)",
      poc_description: "The application fetches remote URLs supplied by the user without validating the destination, enabling access to internal services and cloud metadata.",
      immediate_fix: "Allowlist permitted hostnames; block all private IP ranges.",
      full_fix_code:
        `const ALLOWED = new Set(["api.example.com", "cdn.example.com"]);

function safeFetch(url: string) {
  const { hostname } = new URL(url);
  if (!ALLOWED.has(hostname)) throw new Error("Forbidden host");
  return fetch(url);
}`,
      fix_language: "typescript",
      fix_explanation: "Restricting requests to an allowlist prevents the server from being used as a proxy to internal infrastructure.",
      test_steps: ["Test with http://169.254.169.254/latest/meta-data/", "Test with http://localhost/admin", "Verify both return 400/403"],
      prevention_checklist: ["Use allowlist, never denylist", "Disable internal DNS for user URLs", "Deploy egress firewall", "Monitor outbound requests"],
      cvss_score: "8.8", owasp_category: "A10:2021 – SSRF",
      references: ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
      provider_used: "local",
    };
  }

  if (title.includes("path") || title.includes("traversal") || title.includes("lfi") || cwe.includes("22")) {
    return {
      vulnerability_type: "Path Traversal / LFI",
      poc_description: "User-controlled file paths resolve without sanitisation, allowing ../sequences to escape the intended directory.",
      immediate_fix: "Resolve the full path and verify it starts with the intended base directory before opening.",
      full_fix_code:
        `import path from "path";
const BASE = path.resolve("/app/uploads");

function safeRead(file: string) {
  const resolved = path.resolve(BASE, file);
  if (!resolved.startsWith(BASE + path.sep)) throw new Error("Access denied");
  return fs.readFileSync(resolved, "utf8");
}`,
      fix_language: "typescript",
      fix_explanation: "`path.resolve` collapses all `..` sequences; the prefix check ensures the path stays within the sandbox.",
      test_steps: ["Test with ../../etc/passwd", "Verify 403 is returned", "Confirm /etc/passwd is not in the response"],
      prevention_checklist: ["Always canonicalise paths", "Run as low-privilege user", "Use chroot/container to restrict filesystem", "Never pass user input to file APIs"],
      cvss_score: "7.5", owasp_category: "A01:2021 – Broken Access Control",
      references: ["https://owasp.org/www-community/attacks/Path_Traversal"],
      provider_used: "local",
    };
  }

  if (title.includes("secret") || title.includes("credential") || title.includes("api key") || title.includes("token") || cwe.includes("798")) {
    return {
      vulnerability_type: "Hardcoded Secret / Credential Exposure",
      poc_description: "A secret (API key, password, or token) was found embedded in source code or configuration, visible to anyone with repository access.",
      immediate_fix: "Rotate the exposed credential immediately, then move it to an environment variable or secret manager.",
      full_fix_code:
        `// ❌ Vulnerable
const API_KEY = "sk_live_abc123...";

// ✅ Fixed
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error("API_KEY not set");

# .env  (add to .gitignore)
API_KEY=sk_live_abc123...`,
      fix_language: "bash",
      fix_explanation: "Secrets in environment variables are injected at runtime and never stored in source control.",
      test_steps: ["Confirm credential rotated in provider dashboard", "Search git history: git log -S 'old_key'", "Add gitleaks pre-commit hook"],
      prevention_checklist: ["Use a secret manager (Vault, AWS Secrets Manager)", "Add gitleaks to CI", "Audit .env.example files for real values"],
      cvss_score: "9.1", owasp_category: "A07:2021 – Identification & Authentication Failures",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
      provider_used: "local",
    };
  }

  if (title.includes("jwt") || title.includes("bearer") || cwe.includes("347")) {
    return {
      vulnerability_type: "JWT Security Misconfiguration",
      poc_description: "The JWT implementation accepts tokens signed with the 'none' algorithm or uses a weak secret, enabling authentication bypass.",
      immediate_fix: "Enforce RS256/ES256, reject 'none' algorithm, and validate exp/iss/aud claims on every request.",
      full_fix_code:
        `import jwt from "jsonwebtoken";

// ❌ Vulnerable
const d = jwt.decode(token);

// ✅ Fixed
const d = jwt.verify(token, process.env.JWT_PUBLIC_KEY!, {
  algorithms: ["RS256"],
  issuer: "https://auth.example.com",
  audience: "api.example.com",
});`,
      fix_language: "typescript",
      fix_explanation: "Specifying `algorithms` prevents algorithm confusion; validating claims ensures tokens are scoped correctly.",
      test_steps: ["Send a request with alg:none JWT", "Send an expired token", "Verify both are rejected with 401"],
      prevention_checklist: ["Use RS256/ES256 in production", "Never use HS256 with a short secret", "Set short exp values", "Implement token rotation"],
      cvss_score: "8.1", owasp_category: "A07:2021 – Identification & Authentication Failures",
      references: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
      provider_used: "local",
    };
  }

  // Generic fallback
  return {
    vulnerability_type: v.title || "Security Vulnerability",
    poc_description: v.description || `The finding '${v.title}' represents a security risk that requires investigation and remediation.`,
    immediate_fix: v.remediation || "Review the matched evidence and apply least privilege. Validate all user input and enforce strict output encoding.",
    full_fix_code:
      `// Secure coding fundamentals:
// 1. Validate all input at the boundary
// 2. Encode all output for the target context
// 3. Apply least-privilege to all data access
// 4. Log security-relevant events`,
    fix_language: "javascript",
    fix_explanation: "Defence-in-depth: input validation + output encoding + access control eliminates the vulnerability surface.",
    test_steps: ["Re-run the scanner after the fix", "Manually verify the evidence is no longer exploitable", "Review related code paths for the same pattern"],
    prevention_checklist: ["Add tests covering the vulnerable path", "Integrate SAST into CI/CD", "Conduct a targeted code review"],
    cvss_score: v.severity === "critical" ? "9.0" : v.severity === "high" ? "7.5" : v.severity === "medium" ? "5.0" : "3.1",
    owasp_category: v.owasp || owasp,
    references: v.cwe ? [`https://cwe.mitre.org/data/definitions/${v.cwe.replace(/[^0-9]/g, "")}.html`] : ["https://owasp.org/www-project-top-ten/"],
    provider_used: "local",
  };
}

// ── Main component ───────────────────────────────────────────────────────────

export function AIAdvisor({ vulnerability, pocResult }: AIAdvisorProps) {
  const [loading, setLoading] = useState(false);
  const [pocFix, setPocFix] = useState<PocFix | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);

  const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  const handleGenerateFix = async () => {
    if (loading) return;
    setLoading(true);
    setError(null);
    setPocFix(null);
    setExpanded(true);

    // Enrich the finding with live POC execution evidence if available
    const enrichedFinding = pocResult
      ? {
        ...vulnerability,
        poc_execution: {
          status_code: pocResult.status_code,
          response_time_ms: pocResult.response_time_ms,
          server: pocResult.server,
          content_type: pocResult.content_type,
          verification_status: pocResult.verification_status,
          evidence_match: pocResult.evidence_match,
          secrets_found: (pocResult.secrets_detected || []).length,
          disclosed_headers: pocResult.disclosed_headers || [],
          response_snippet: pocResult.body_pretty?.slice(0, 500) || "",
        },
      }
      : vulnerability;

    try {
      const res = await fetch(`${API_BASE}/api/v1/ai/poc-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: enrichedFinding }),
        signal: AbortSignal.timeout(8000),
      });

      const data = await res.json();

      if (data.success && data.poc_fix) {
        setPocFix(data.poc_fix);
        toast.success("Fix intelligence generated", {
          description: `Powered by ${PROVIDER_LABELS[data.poc_fix.provider_used] ?? data.poc_fix.provider_used}`,
        });
        return;
      }
      // AI providers unavailable → fall through to local generator
    } catch {
      // Network error or timeout → fall through to local generator
    }

    // Local offline fallback — always produces a result
    const localFix = generateLocalFix(vulnerability);
    setPocFix(localFix);
    toast.success("Fix intelligence generated", {
      description: "Powered by local rule engine (AI providers offline)",
    });
    setLoading(false);
  };

  return (
    <div className="bg-gradient-to-br from-primary/10 to-blue-500/5 border border-primary/20 rounded-2xl p-6 relative overflow-hidden group h-full flex flex-col">
      {/* Background pattern */}
      <div className="absolute -top-10 -right-10 opacity-[0.05] group-hover:scale-110 group-hover:opacity-[0.08] transition-all duration-700 pointer-events-none">
        <Bot className="w-48 h-48 rotate-12" />
      </div>

      {/* Header */}
      <div className="flex items-center gap-3 mb-6 relative z-10">
        <div className="w-10 h-10 rounded-xl bg-primary flex items-center justify-center p-0.5 shadow-[0_0_15px_rgba(var(--primary),0.3)]">
          <div className="w-full h-full bg-background rounded-[9px] flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-primary" />
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <h4 className="text-xs font-black text-foreground uppercase tracking-tighter">AI Security Advisor</h4>
          <p className="text-[10px] text-primary font-black uppercase tracking-widest mt-0.5">
            Neural Security Analysis · Multi-LLM
          </p>
        </div>
        {pocResult?.verification_status === "VERIFIED" && (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-primary/10 border border-primary/20 shrink-0">
            <ShieldCheck className="w-3 h-3 text-primary" />
            <span className="text-[8px] font-black text-primary uppercase tracking-widest">Live Evidence</span>
          </div>
        )}
      </div>

      {/* Static analysis (always shown) */}
      <div className="space-y-6 relative z-10 flex-1">
        {/* Expert synthesis */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase tracking-widest">
            <MessageSquare className="w-3 h-3" />
            Expert Synthesis
          </div>
          <p className="text-[11px] text-muted-foreground/80 leading-relaxed bg-secondary/40 border border-border rounded-xl p-4 italic">
            {vulnerability.description
              ? `"${vulnerability.description}"`
              : `"This ${vulnerability.title || "vulnerability"} poses a security risk to the target system. Review matched evidence and apply the recommended remediation immediately."`}
          </p>
        </div>

        {/* Static remediation hint */}
        {vulnerability.remediation && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase tracking-widest">
              <Lightbulb className="w-3 h-3 text-yellow-500" />
              Recommended Remediation
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed bg-secondary border border-border rounded-xl p-3">
              {vulnerability.remediation}
            </p>
          </div>
        )}

        {/* Validation strategy */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-bold uppercase tracking-widest">
            <Lightbulb className="w-3 h-3 text-yellow-500" />
            Validation Strategy
          </div>
          <ul className="space-y-2">
            {[
              vulnerability.cwe ? `Verify ${vulnerability.cwe} impact scope` : "Confirm vulnerability scope",
              "Analyze response for data leakage indicators",
              "Document proof-of-concept evidence",
            ].map((step, i) => (
              <li key={i} className="flex items-center gap-3 group/item cursor-pointer">
                <div className="w-5 h-5 rounded-full bg-secondary border border-border flex items-center justify-center text-[10px] font-black text-primary group-hover/item:border-primary/40 transition-all">
                  {i + 1}
                </div>
                <span className="text-[10px] text-muted-foreground font-bold uppercase tracking-[0.05em] group-hover/item:text-foreground transition-colors">
                  {step}
                </span>
                <ArrowRight className="w-3 h-3 text-muted-foreground ml-auto group-hover/item:text-primary group-hover/item:translate-x-1 transition-all" />
              </li>
            ))}
          </ul>
        </div>

        {/* ── AI Fix Intelligence Panel ─────────────────────── */}
        {expanded && (
          <div className="border-t border-primary/10 pt-4 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-[10px] text-primary font-bold uppercase tracking-widest">
                <ShieldCheck className="w-3 h-3" />
                AI Fix Intelligence
              </div>
              <button
                type="button"
                onClick={() => setExpanded(false)}
                aria-label="Collapse fix intelligence panel"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>

            {/* Loading */}
            {loading && (
              <div className="flex items-center gap-3 py-6 justify-center">
                <Loader2 className="w-4 h-4 text-primary animate-spin" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">
                  Generating fix intelligence...
                </span>
              </div>
            )}

            {/* Error */}
            {error && !loading && (
              <div className="flex items-start gap-2 p-3 rounded-xl bg-red-500/5 border border-red-500/20">
                <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                <p className="text-[10px] text-red-400 leading-relaxed">{error}</p>
              </div>
            )}

            {/* Fix results */}
            {pocFix && !loading && (
              <div className="space-y-4">

                {/* Provider + CVSS row */}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">Powered by</span>
                  <ProviderBadge provider={pocFix.provider_used} />
                  {pocFix.cvss_score && (
                    <>
                      <span className="text-muted-foreground/30">•</span>
                      <span className="text-[9px] text-orange-400 font-black uppercase tracking-widest">
                        CVSS {pocFix.cvss_score}
                      </span>
                    </>
                  )}
                  {pocFix.owasp_category && (
                    <>
                      <span className="text-muted-foreground/30">•</span>
                      <span className="text-[9px] text-primary/70 font-bold">{pocFix.owasp_category}</span>
                    </>
                  )}
                </div>

                {/* POC Description */}
                <div className="space-y-1">
                  <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                    POC Confirms
                  </div>
                  <p className="text-[11px] text-muted-foreground/80 leading-relaxed bg-secondary border border-border rounded-xl p-3 italic">
                    {pocFix.poc_description}
                  </p>
                </div>

                {/* Immediate fix */}
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5 text-[9px] text-yellow-400 uppercase tracking-widest font-bold">
                    <Zap className="w-3 h-3" />
                    Immediate Fix
                  </div>
                  <div className="text-[11px] text-yellow-300 bg-yellow-400/5 border border-yellow-400/15 rounded-xl p-3 font-mono leading-relaxed">
                    {pocFix.immediate_fix}
                  </div>
                </div>

                {/* Full fix code */}
                <div className="space-y-1.5">
                  <div className="text-[9px] text-primary uppercase tracking-widest font-bold">
                    Full Fix Code
                  </div>
                  <CodeBlock code={pocFix.full_fix_code} language={pocFix.fix_language} />
                </div>

                {/* Fix explanation */}
                <div className="space-y-1">
                  <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                    Why This Fix Works
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-relaxed">{pocFix.fix_explanation}</p>
                </div>

                {/* Test steps */}
                {pocFix.test_steps.length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5 text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                      <ClipboardList className="w-3 h-3" />
                      Verification Steps
                    </div>
                    <ul className="space-y-1.5">
                      {pocFix.test_steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <div className="w-4 h-4 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-[9px] font-black text-primary shrink-0 mt-0.5">
                            {i + 1}
                          </div>
                          <span className="text-[10px] text-muted-foreground leading-relaxed">{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Prevention checklist */}
                {pocFix.prevention_checklist.length > 0 && (
                  <div className="space-y-2">
                    <div className="flex items-center gap-1.5 text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                      <CheckCircle2 className="w-3 h-3 text-primary" />
                      Prevention Checklist
                    </div>
                    <ul className="space-y-1">
                      {pocFix.prevention_checklist.map((item, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-primary text-[10px] shrink-0">▸</span>
                          <span className="text-[10px] text-muted-foreground leading-relaxed">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* References */}
                {pocFix.references.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
                      References
                    </div>
                    <div className="space-y-1">
                      {pocFix.references.map((ref, i) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1.5 text-[10px] text-primary/60 hover:text-primary transition-colors group/ref"
                        >
                          <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                          <span className="truncate">{ref}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Generate Fix Button ────────────────────────────── */}
        <div className={cn("pt-4 mt-auto", expanded && pocFix && "pt-2")}>
          <button
            type="button"
            onClick={!pocFix ? handleGenerateFix : () => setExpanded((v) => !v)}
            disabled={loading}
            className={cn(
              "w-full flex items-center justify-between gap-3 px-5 py-3 rounded-xl border transition-all",
              !pocFix
                ? "bg-primary/10 border-primary/20 hover:bg-primary/20 group/btn"
                : "bg-primary/5 border-primary/15 hover:bg-primary/10",
              loading && "opacity-70 cursor-not-allowed",
            )}
          >
            <div className="flex items-center gap-2">
              {loading ? (
                <Loader2 className="w-4 h-4 text-primary animate-spin" />
              ) : pocFix ? (
                <CheckCircle2 className="w-4 h-4 text-primary" />
              ) : (
                <ShieldCheck className="w-4 h-4 text-primary" />
              )}
              <span className="text-[10px] text-foreground font-black uppercase tracking-widest">
                {loading
                  ? "Generating..."
                  : pocFix
                    ? expanded
                      ? "Collapse Fix Intelligence"
                      : "Show Fix Intelligence"
                    : "Generate Fix Intelligence"}
              </span>
            </div>
            {!loading && (
              pocFix
                ? expanded
                  ? <ChevronUp className="w-3 h-3 text-primary" />
                  : <ChevronDown className="w-3 h-3 text-primary" />
                : <Zap className="w-3 h-3 text-primary animate-pulse" />
            )}
          </button>
          {!pocFix && !loading && (
            <p className="text-[9px] text-center text-muted-foreground mt-2 uppercase tracking-widest font-bold">
              Powered by Gemini → Claude → GPT fallback chain
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
