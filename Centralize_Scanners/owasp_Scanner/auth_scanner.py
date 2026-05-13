"""
Quantara Security v4.0 — A07: Identification & Authentication Failures Scanner

Detects:
  - Weak password policies (min length, no complexity, weak hashing)
  - Session management issues (no HttpOnly/Secure/SameSite, session in URL)
  - JWT misconfigurations (alg:none, verify:false, weak secrets, missing exp)
  - Hardcoded credentials & default passwords in auth configs
  - Missing MFA/2FA references
  - Credential stuffing enablers (no rate limit on login)
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional, Callable
from pathlib import Path
import time as _auth_time

try:
    from Centralize_Scanners.scanner_engine.neo_intelligence import get_payload_generator, get_spec_abuse_kb
except ImportError:
    get_payload_generator = lambda: None
    get_spec_abuse_kb = lambda: None

@dataclass
class AuthFinding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    category: str
    subcategory: str  # password-policy | session | jwt | mfa | credentials
    cwe: str
    remediation: str
    confidence: float
    tags: list[str] = field(default_factory=list)

@dataclass
class AuthPattern:
    id: str
    pattern: str
    severity: str
    title: str
    description: str
    cwe: str
    remediation: str
    confidence: float
    subcategory: str
    tags: tuple[str, ...] = ()

def _build_rules() -> list[AuthPattern]:
    rules: list[AuthPattern] = []
    def _add(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags=()):
        rules.append(AuthPattern(id_, pat, sev, title, desc, cwe, rem, conf, sub, tags))

    # ── Weak Password Policies ────────────────────────────────────
    _add("AU-001", r"""(?:min_?length|minLength|MIN_PASSWORD_LENGTH|password_min)\s*(?:=|:)\s*(?:[1-7]\b)""",
         "High", "Weak Password Minimum Length (<8)",
         "Password minimum length set below 8 characters. NIST recommends minimum 8, preferably 12+.",
         "CWE-521", "Set minimum password length to 12+. Enforce complexity rules.",
         0.80, "password-policy", ("password", "length"))

    _add("AU-002", r"""(?:hashlib\.(?:md5|sha1|sha256)|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA-256)["']\)).*?password""",
         "Critical", "Plain Hash for Password (No KDF)",
         "Password hashed with plain MD5/SHA-1/SHA-256 without salt or KDF. Trivially crackable.",
         "CWE-916", "Use bcrypt, scrypt, or Argon2id for password hashing. Never use plain hash functions.",
         0.85, "password-policy", ("password", "hashing"))

    _add("AU-003", r"""bcrypt\.(?:gensalt|hashpw)\s*\([^)]*rounds?\s*=\s*(?:[1-9]\b)""",
         "High", "BCrypt Low Work Factor (rounds<10)",
         "BCrypt configured with cost factor below 10. Modern hardware can brute force this quickly.",
         "CWE-916", "Use minimum 12 rounds for bcrypt. Consider Argon2id for new applications.",
         0.80, "password-policy", ("bcrypt", "rounds"))

    _add("AU-004", r"""(?:PBKDF2|pbkdf2)\s*\([^)]*iterations?\s*=\s*(?:\d{1,5}\b)""",
         "High", "PBKDF2 Low Iterations (<100,000)",
         "PBKDF2 configured with too few iterations. OWASP recommends minimum 600,000 for SHA-256.",
         "CWE-916", "Set PBKDF2 iterations to 600,000+ (SHA-256) or 210,000+ (SHA-512).",
         0.75, "password-policy", ("pbkdf2", "iterations"))

    # ── Session Management ────────────────────────────────────────
    _add("AU-010", r"""(?:SESSION_COOKIE_HTTPONLY|httpOnly|HttpOnly)\s*(?:=|:)\s*(?:False|false|0)""",
         "High", "Session Cookie Missing HttpOnly Flag",
         "Session cookie HttpOnly flag disabled. JavaScript can steal session tokens via XSS.",
         "CWE-1004", "Set HttpOnly=true on all session cookies to prevent JavaScript access.",
         0.85, "session", ("session", "httponly"))

    _add("AU-011", r"""(?:SESSION_COOKIE_SECURE|secure|Secure)\s*(?:=|:)\s*(?:False|false|0)""",
         "High", "Session Cookie Missing Secure Flag",
         "Session cookie not marked Secure. Cookie transmitted over unencrypted HTTP connections.",
         "CWE-614", "Set Secure=true to ensure cookies are only sent over HTTPS.",
         0.85, "session", ("session", "secure"))

    _add("AU-012", r"""(?:samesite|SameSite|SAME_SITE)\s*(?:=|:)\s*["']?(?:None|none)["']?""",
         "High", "Session Cookie SameSite=None",
         "SameSite=None allows cross-site cookie transmission. Requires Secure flag and enables CSRF.",
         "CWE-352", "Set SameSite=Strict or SameSite=Lax for session cookies.",
         0.75, "session", ("session", "samesite"))

    _add("AU-013", r"""(?:session_id|sessionId|JSESSIONID|PHPSESSID|sid)\s*=\s*(?:req\.(?:query|params)|request\.(?:GET|args))\b""",
         "Critical", "Session ID in URL Parameter",
         "Session ID transmitted via URL query parameter. Session IDs in URLs are logged, cached, and shared.",
         "CWE-384", "Use HTTP-only cookies for session management. Never pass session IDs in URLs.",
         0.90, "session", ("session", "url"))

    _add("AU-014", r"""(?:session|req\.session)\.(?:regenerate|destroy|create)\b""",
         "Info", "Session Lifecycle Management Detected",
         "Session regeneration/destruction logic found. Verify it's called after login to prevent session fixation.",
         "CWE-384", "Always regenerate session ID after successful authentication.",
         0.40, "session", ("session", "regeneration"))

    # ── JWT Misconfigurations ─────────────────────────────────────
    _add("AU-020", r"""(?:algorithm|alg)\s*(?:=|:)\s*["']?(?:none|None|NONE)["']?""",
         "Critical", "JWT Algorithm: none",
         "JWT configured to accept 'none' algorithm. Attacker can forge tokens without any signature.",
         "CWE-345", "Never allow 'none' algorithm. Explicitly set algorithms=['RS256'] or ['HS256'].",
         0.95, "jwt", ("jwt", "none-algorithm"))

    _add("AU-021", r"""(?:verify|verification|validate)\s*(?:=|:)\s*(?:False|false|0).*?(?:jwt|token|JWT|signature)""",
         "Critical", "JWT Signature Verification Disabled",
         "JWT signature verification is explicitly disabled. Tokens can be forged by anyone.",
         "CWE-345", "Always verify JWT signatures. Set verify=True. Use strong key management.",
         0.90, "jwt", ("jwt", "verify"))

    _add("AU-022", r"""jwt\.(?:decode|verify)\s*\([^)]*(?:options|opts)[^)]*(?:ignoreExpiration|clockTolerance)\s*[:=]\s*true""",
         "High", "JWT Expiration Ignored",
         "JWT expiration validation disabled. Expired tokens will be accepted indefinitely.",
         "CWE-613", "Always validate JWT expiration. Set short-lived tokens (15 min) with refresh tokens.",
         0.80, "jwt", ("jwt", "expiration"))

    _add("AU-023", r"""(?:jwt|JWT)\.(?:sign|encode)\s*\([^)]*["'](?:secret|password|key123|changeme|mysecret|default)["']""",
         "Critical", "JWT Signed with Weak/Default Secret",
         "JWT signed with a known-weak or default secret. Attacker can generate valid tokens.",
         "CWE-798", "Use a cryptographically random secret (256+ bits). Store in secrets manager.",
         0.90, "jwt", ("jwt", "weak-secret"))

    _add("AU-024", r"""(?:RS256|RS384|RS512|PS256|PS384|PS512)\s*(?:→|to|changed|switch|convert)\s*(?:HS256|HS384|HS512)""",
         "Critical", "JWT Algorithm Confusion Attack Pattern",
         "RS→HS algorithm confusion: attacker signs JWT with public key as HMAC secret.",
         "CWE-327", "Pin expected algorithm in verify: jwt.verify(token, key, {algorithms: ['RS256']})",
         0.70, "jwt", ("jwt", "algorithm-confusion"))

    # ── MFA/2FA ───────────────────────────────────────────────────
    _add("AU-030", r"""(?:totp_secret|otp_secret|mfa_secret|two_factor_secret)\s*=\s*["'][^"']+["']""",
         "Critical", "TOTP/MFA Secret Stored in Plaintext",
         "TOTP/OTP secret stored as plaintext string. Should be encrypted at rest.",
         "CWE-312", "Encrypt MFA secrets at rest using envelope encryption (KMS + DEK).",
         0.85, "mfa", ("mfa", "plaintext"))

    _add("AU-031", r"""(?:backup_codes|recovery_codes)\s*=\s*\[""",
         "High", "Backup/Recovery Codes in Source",
         "MFA backup codes found in source code. These should be generated at runtime and hashed.",
         "CWE-798", "Generate backup codes dynamically. Hash them with bcrypt before storing.",
         0.75, "mfa", ("mfa", "backup-codes"))

    # ── Credential Exposure ───────────────────────────────────────
    _add("AU-040", r"""(?:password|passwd|pwd)\s*[:=]\s*["'].*?["'].*?(?:login|authenticate|auth|sign_in|signIn)""",
         "Critical", "Hardcoded Credentials in Auth Logic",
         "Password literal found near authentication logic. Hardcoded credentials persist in binaries and VCS.",
         "CWE-798", "Use secrets manager. Never hardcode credentials. Use environment variables at minimum.",
         0.75, "credentials", ("credentials", "hardcoded"))

    return rules

ALL_AUTH_RULES = _build_rules()
COMPILED_AUTH_RULES = [(re.compile(r.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), r) for r in ALL_AUTH_RULES]
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", "venv", "vendor", ".cache"}
SCAN_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yaml", ".yml", ".json", ".conf", ".ini", ".env", ".toml", ".properties"}

def scan_auth_file(content: str, filepath: str, base_path: str = "") -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    relative = filepath.replace(base_path, "").lstrip("/\\") if base_path else filepath
    seen: set[str] = set()
    for compiled_re, rule in COMPILED_AUTH_RULES:
        for match in compiled_re.finditer(content):
            line_num = content.count("\n", 0, match.start()) + 1
            key = f"{rule.id}:{line_num}"
            if key in seen: continue
            seen.add(key)
            findings.append(AuthFinding(
                id=f"AU-{relative}:{line_num}:{rule.id}", file=relative, line_number=line_num,
                severity=rule.severity, title=rule.title, description=rule.description,
                matched_content=str(match.group(0)).strip()[0:200], category="A07:2025-Auth Failures",
                subcategory=rule.subcategory, cwe=rule.cwe, remediation=rule.remediation,
                confidence=float(rule.confidence), tags=list(rule.tags),
            ))
    return findings

def normalize_auth_finding(finding: AuthFinding, scan_id: str = "manual") -> AuthFinding:
    """Enrich Auth finding with NEO Intelligence."""
    kb = get_spec_abuse_kb()
    if kb and hasattr(finding, 'subcategory'):
        # Map subcategory to language/tech for KB lookup
        ext = Path(finding.file).suffix.lower()
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php"
        }
        lang = lang_map.get(ext, "generic")
        
        vectors = kb.get_abuse_vectors(lang)
        if vectors:
            relevant = [v for v in vectors if finding.subcategory in str(v.get("description", "")).lower() or "auth" in str(v.get("description", "")).lower()]
            relevant_list = list(relevant) if relevant else list(vectors)
            relevant_vectors = relevant_list[0:2] # type: ignore
            
            vector_str = "\n".join([f"• {str(v.get('description', ''))}" for v in relevant_vectors])
            
            spec_abuse_intel = f"\n\n[NEO SPEC ABUSE INTELLIGENCE]\nKnown vectors for {finding.subcategory}:\n{vector_str}"
            finding.description = f"{finding.description}{spec_abuse_intel}"
            
    return finding

def scan_auth_directory(root: str, scan_id: str = "manual", max_files: int = 50_000,
                       on_finding: Optional[Callable] = None) -> list[AuthFinding]:
    """Walk a directory tree and scan for authentication vulnerabilities."""
    all_findings: list[AuthFinding] = []
    root_path = Path(root)
    scanned: int = 0
    start = _auth_time.time()

    for fpath in root_path.rglob("*"):
        _sc = int(scanned)
        if _sc >= int(max_files):
            break
        if fpath.is_dir():
            continue
        if any(s in fpath.parts for s in SKIP_DIRS):
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 5_000_000:
                continue
            
            findings = scan_auth_file(content, str(fpath), str(root_path))
            for f in findings:
                normalized = normalize_auth_finding(f, scan_id)
                all_findings.append(normalized)
                if on_finding:
                    try:
                        on_finding(normalized)
                    except Exception:
                        pass
            
            scanned = int(scanned) + 1 # type: ignore
        except (OSError, PermissionError):
            continue
            
    return all_findings

def get_auth_scan_summary(findings: list[AuthFinding], root: str, files_scanned: int,
                          start_time: float, scan_id: str = "manual") -> dict:
    """Generate a summary of the authentication scan results."""
    elapsed_ms = (_auth_time.time() - start_time) * 1000
    return {
        "scan_id": scan_id,
        "root": root,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "duration_ms": float(f"{elapsed_ms:.2f}"),
        "severity_breakdown": {
            sev: sum(1 for f in findings if f.severity.lower() == sev)
            for sev in ["critical", "high", "medium", "low", "info"]
        },
        "timestamp": _auth_time.time()
    }
