// ─────────────────────────────────────────────────────────────────────────────
// Quantara Documentation Content
// All documentation articles defined as structured TypeScript data.
// ─────────────────────────────────────────────────────────────────────────────

export type BlockType =
  | "paragraph"
  | "heading2"
  | "heading3"
  | "heading4"
  | "code"
  | "note"
  | "warning"
  | "tip"
  | "step"
  | "list"
  | "ordered-list"
  | "table"
  | "image-placeholder"
  | "image"
  | "divider"
  | "badge-row";

export interface ParagraphBlock {
  type: "paragraph";
  content: string;
}
export interface HeadingBlock {
  type: "heading2" | "heading3" | "heading4";
  content: string;
  id?: string;
}
export interface CodeBlock {
  type: "code";
  language?: string;
  content: string;
  filename?: string;
}
export interface CalloutBlock {
  type: "note" | "warning" | "tip";
  title?: string;
  content: string;
}
export interface StepBlock {
  type: "step";
  number: number;
  title: string;
  content: string;
}
export interface ListBlock {
  type: "list" | "ordered-list";
  items: string[];
}
export interface TableBlock {
  type: "table";
  headers: string[];
  rows: string[][];
}
export interface ImagePlaceholderBlock {
  type: "image-placeholder";
  caption: string;
  label?: string;
}
export interface ImageBlock {
  type: "image";
  src: string;
  caption: string;
  label?: string;
  alt?: string;
}
export interface DividerBlock {
  type: "divider";
}
export interface BadgeRowBlock {
  type: "badge-row";
  items: { label: string; color: "green" | "red" | "orange" | "blue" | "gray" }[];
}

export type DocBlock =
  | ParagraphBlock
  | HeadingBlock
  | CodeBlock
  | CalloutBlock
  | StepBlock
  | ListBlock
  | TableBlock
  | ImagePlaceholderBlock
  | ImageBlock
  | DividerBlock
  | BadgeRowBlock;

export interface DocArticle {
  slug: string;
  title: string;
  description: string;
  category: string;
  estimatedRead: number; // minutes
  lastUpdated: string;
  content: DocBlock[];
}

export interface DocSection {
  id: string;
  title: string;
  icon: string;
  description: string;
  articles: DocArticle[];
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1: GETTING STARTED
// ─────────────────────────────────────────────────────────────────────────────

const gettingStarted: DocSection = {
  id: "getting-started",
  title: "Getting Started",
  icon: "rocket",
  description: "New to Quantara? Start here.",
  articles: [
    {
      slug: "getting-started",
      title: "What is Quantara?",
      description: "An introduction to the Quantara Security platform and its core capabilities.",
      category: "Getting Started",
      estimatedRead: 4,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara is an enterprise-grade security scanning platform designed to help development teams, security analysts, and DevSecOps engineers identify, understand, and remediate web application vulnerabilities — before attackers do." },
        { type: "image", src: "/Dashboard Screenshot.png", caption: "Quantara Dashboard Overview", label: "Dashboard" },
        { type: "heading2", content: "Why Quantara?", id: "why-quantara" },
        { type: "paragraph", content: "Modern web applications are complex, fast-changing, and exposed to thousands of attack vectors. Traditional static analysis tools miss runtime behavior; manual penetration tests are expensive and infrequent. Quantara bridges this gap with continuous, intelligent scanning that adapts to your application's evolving attack surface." },
        { type: "heading2", content: "Core Capabilities", id: "core-capabilities" },
        {
          type: "list", items: [
            "OWASP Top 10 vulnerability detection across 11+ scanner modules",
            "Real-time findings streamed via Server-Sent Events (SSE)",
            "AI-powered exploit verification and confidence scoring",
            "Automated attack path analysis and breach simulation",
            "AI Security Copilot for natural-language remediation guidance",
            "Dashboard with risk scoring, metrics, and visual attack graphs",
            "Subscription-based tiers: Free, Pro, and Enterprise",
          ]
        },
        { type: "heading2", content: "Who Is It For?", id: "who-is-it-for" },
        {
          type: "table", headers: ["Role", "How They Use Quantara"], rows: [
            ["Security Analyst", "Run deep scans, investigate findings, generate reports"],
            ["Developer", "Scan during development to catch vulnerabilities early"],
            ["DevSecOps Engineer", "Integrate into CI/CD for continuous security monitoring"],
            ["CISO / Security Manager", "Dashboard metrics, risk scoring, compliance evidence"],
            ["Penetration Tester", "Automated reconnaissance + exploit verification baseline"],
          ]
        },
        { type: "heading2", content: "Key Concepts", id: "key-concepts" },
        { type: "heading3", content: "Scan" },
        { type: "paragraph", content: "A scan is a targeted security assessment of a URL or web application. Quantara orchestrates multiple scanner modules in parallel, each probing specific vulnerability classes." },
        { type: "heading3", content: "Finding" },
        { type: "paragraph", content: "A finding is a confirmed or suspected vulnerability discovered during a scan. Each finding includes a severity rating, confidence score, evidence, and AI-generated remediation guidance." },
        { type: "heading3", content: "Risk Score" },
        { type: "paragraph", content: "The Risk Score (0–100) reflects the overall security posture of a scanned target. A score of 0 is critical; 100 is ideal (no issues). Scores are weighted by severity, coverage, and confidence." },
        { type: "tip", title: "Get started in 2 minutes", content: "Create a free account, enter a target URL, and click 'Start Scan'. Your first results will begin streaming in real-time within seconds." },
      ],
    },
    {
      slug: "platform-overview",
      title: "Platform Overview",
      description: "Explore Quantara's architecture, scanner modules, and platform components.",
      category: "Getting Started",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara is built as a full-stack security platform. Understanding its architecture helps you get the most out of every scan and interpret results with precision." },
        { type: "heading2", content: "Platform Architecture", id: "platform-architecture" },
        { type: "image", src: "/Architecture Diagram.png", caption: "Platform Architecture Diagram", label: "Architecture" },
        { type: "heading3", content: "Frontend (Next.js 16)" },
        { type: "paragraph", content: "The web application is built with Next.js 16 using the App Router. It connects to the backend over REST APIs and receives live scan updates via Server-Sent Events (SSE), giving you a real-time view of scan progress and findings." },
        { type: "heading3", content: "Backend (FastAPI)" },
        { type: "paragraph", content: "The FastAPI backend manages authentication, scan orchestration, database persistence, and external integrations. All API endpoints are versioned under /api/v1/." },
        { type: "heading3", content: "Scanner Engine" },
        { type: "paragraph", content: "The Scanner Engine is the core intelligence layer. It coordinates 11+ specialized scanner modules, each targeting specific vulnerability categories. Results are normalized, deduplicated, and fed into the AI verification pipeline." },
        { type: "heading2", content: "Scanner Modules", id: "scanner-modules" },
        {
          type: "table", headers: ["Module", "OWASP Category", "Description"], rows: [
            ["Security Scanner", "A01–A10", "Full OWASP Top 10 coverage sweep"],
            ["Injection Scanner", "A03 Injection", "SQL, Command, LDAP, NoSQL injection detection"],
            ["Misconfiguration Engine", "A05 Security Misconfiguration", "Server headers, CORS, CSP, exposed admin panels"],
            ["Endpoint Extractor", "Discovery", "Hidden routes, API endpoints, file exposure"],
            ["Frontend JS Analyzer", "A06 Vulnerable Components", "Client-side secrets, unsafe eval, vulnerable libraries"],
            ["Exploit Verification Engine", "All", "Proof-based exploit confirmation with confidence scoring"],
            ["Attack Path Analyzer", "All", "Multi-step attack chain visualization"],
          ]
        },
        { type: "heading2", content: "Data Flow", id: "data-flow" },
        { type: "paragraph", content: "When you initiate a scan, the following happens:" },
        {
          type: "ordered-list", items: [
            "Target URL validated and scan job created (UUID assigned)",
            "Scanner Engine spawns parallel module workers",
            "Findings stream in real-time to your browser via SSE",
            "AI Exploit Verifier confirms and scores each finding",
            "Attack Path Analyzer chains related findings into breach paths",
            "Risk Score computed and dashboard updated",
            "AI Copilot generates remediation guidance",
          ]
        },
        { type: "heading2", content: "Infrastructure", id: "infrastructure" },
        {
          type: "list", items: [
            "PostgreSQL — persistent storage for scans, findings, users",
            "Redis — real-time scan state, event pub/sub",
            "Celery — async background scan job processing",
            "Firebase — frontend authentication",
            "Stripe — subscription billing",
          ]
        },
      ],
    },
    {
      slug: "dashboard-walkthrough",
      title: "Dashboard Walkthrough",
      description: "A visual guide to every section of the Quantara dashboard.",
      category: "Getting Started",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Quantara Dashboard is your command center. This walkthrough explains every panel, metric, and control so you can navigate confidently." },
        { type: "image", src: "/Dashboard Screenshot.png", caption: "Full Dashboard View", label: "Dashboard" },
        { type: "heading2", content: "Navigation Sidebar", id: "navigation-sidebar" },
        { type: "paragraph", content: "The left sidebar provides navigation across the platform. It shows your current subscription tier and can be collapsed to maximize screen space." },
        {
          type: "list", items: [
            "Homepage — Return to the landing page",
            "Dashboard — Your main security overview",
            "Security Scanner — Launch and monitor scans",
            "Documentation — This documentation portal",
            "Settings — Account preferences",
            "Billing — Subscription management",
          ]
        },
        { type: "heading2", content: "Security Metrics Cards", id: "security-metrics-cards" },
        { type: "image", src: "/Dashboard Screenshot.png", caption: "Security Metrics Panel", label: "Metrics" },
        { type: "paragraph", content: "The top metrics row displays your real-time security posture:" },
        {
          type: "table", headers: ["Metric", "What It Means"], rows: [
            ["Risk Score", "0–100 score reflecting overall security health. Higher is safer."],
            ["Total Findings", "Count of all identified vulnerabilities across all scans"],
            ["Critical Issues", "Findings rated CRITICAL severity — fix immediately"],
            ["Scans Run", "Total number of scans executed on your account"],
            ["Coverage", "Percentage of your attack surface that has been assessed"],
            ["Verified Exploits", "Findings confirmed as exploitable by the AI Exploit Verifier"],
          ]
        },
        { type: "heading2", content: "Scanner Tab", id: "scanner-tab" },
        { type: "paragraph", content: "The Scanner tab is where you configure and launch scans. Enter a target URL, choose scan depth, and click Start Scan. Results stream in real-time below." },
        { type: "heading2", content: "Findings Tab", id: "findings-tab" },
        { type: "paragraph", content: "The Findings tab lists all discovered vulnerabilities. Each finding shows:" },
        {
          type: "list", items: [
            "Severity badge (Critical / High / Medium / Low / Informational)",
            "Vulnerability type and OWASP category",
            "Target URL and affected parameter",
            "Confidence score (AI verification result)",
            "Evidence snippet",
            "Remediation priority",
          ]
        },
        { type: "heading2", content: "History Tab", id: "history-tab" },
        { type: "paragraph", content: "The History tab shows all past scans with their completion status, finding counts, and risk scores. Click any scan to view its detailed results." },
        { type: "tip", title: "Keyboard Shortcuts", content: "Quantara supports keyboard shortcuts. Press '?' anywhere in the dashboard to view the shortcut reference panel." },
      ],
    },
    {
      slug: "first-scan",
      title: "Your First Scan",
      description: "Step-by-step guide to running your first security scan with Quantara.",
      category: "Getting Started",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Running your first scan takes less than 2 minutes. Follow these steps to get immediate security insights on any web target." },
        { type: "note", title: "Before you begin", content: "Ensure you have authorization to scan the target. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal and violates our Terms of Service." },
        { type: "step", number: 1, title: "Log in to your account", content: "Visit the Quantara dashboard and sign in with your credentials. New users can create a free account in under 60 seconds." },
        { type: "step", number: 2, title: "Navigate to the Scanner", content: "Click 'Security Scanner' in the left sidebar, or click the 'Scanner' tab in your dashboard." },
        { type: "image", src: "/Scanner Config Screenshot.png", caption: "Scanner Configuration Panel", label: "Configuration" },
        { type: "step", number: 3, title: "Enter the target URL", content: "Type the full URL of the web application you want to scan. Include the protocol (https://). Example: https://testapp.example.com" },
        { type: "step", number: 4, title: "Configure scan options (optional)", content: "For your first scan, the default settings work well. Advanced users can configure scan depth, module selection, and rate limiting under 'Advanced Options'." },
        { type: "step", number: 5, title: "Click Start Scan", content: "Click the green 'Start Scan' button. Quantara immediately begins scanning and findings start streaming in real-time." },
        { type: "image", src: "/Real-time Scan Screenshot.png", caption: "Live Scan Progress Stream", label: "Real-time Stream" },
        { type: "step", number: 6, title: "Monitor progress", content: "Watch findings appear in real-time in the findings panel. The scanner shows progress per module and logs each probe." },
        { type: "step", number: 7, title: "Review results", content: "When the scan completes, review your Risk Score, browse findings by severity, and use AI Copilot to get remediation guidance for any finding." },
        { type: "tip", title: "Use a test application", content: "For your first scan, consider using a deliberately vulnerable practice application like DVWA, WebGoat, or Juice Shop to safely learn the platform before scanning production systems." },
      ],
    },
    {
      slug: "understanding-results",
      title: "Understanding Scan Results",
      description: "Learn how to read and interpret Quantara's vulnerability findings and risk scores.",
      category: "Getting Started",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara returns rich, structured vulnerability data. This guide explains how to read every field so you can prioritize and act effectively." },
        { type: "heading2", content: "Severity Levels", id: "severity-levels" },
        { type: "paragraph", content: "Every finding is assigned a severity based on potential impact and exploitability:" },
        {
          type: "table", headers: ["Severity", "CVSS Range", "Action Required"], rows: [
            ["Critical", "9.0–10.0", "Fix immediately — active exploitation likely"],
            ["High", "7.0–8.9", "Fix within 24–72 hours"],
            ["Medium", "4.0–6.9", "Schedule fix within sprint"],
            ["Low", "0.1–3.9", "Fix in next planned maintenance"],
            ["Informational", "0.0", "Review — no immediate action required"],
          ]
        },
        { type: "heading2", content: "Confidence Score", id: "confidence-score" },
        { type: "paragraph", content: "The confidence score (0–100%) reflects how certain the AI Exploit Verifier is that a finding is a real vulnerability, not a false positive." },
        {
          type: "list", items: [
            "90–100%: Verified — AI confirmed exploitability with proof",
            "70–89%: High confidence — strong evidence, likely real",
            "50–69%: Medium confidence — possible, warrants manual review",
            "Below 50%: Low confidence — possible false positive",
          ]
        },
        { type: "heading2", content: "Understanding the Risk Score", id: "risk-score" },
        { type: "paragraph", content: "The Risk Score is a composite metric calculated from:" },
        {
          type: "ordered-list", items: [
            "Severity distribution of findings (Critical and High weighted heavily)",
            "Scan coverage percentage (how much of the attack surface was assessed)",
            "Confidence scores of findings",
            "Verified exploit count",
          ]
        },
        { type: "note", content: "A score of 100 does not mean your application is perfectly secure — it means Quantara found no issues within its scan coverage. Always strive for maximum coverage." },
        { type: "heading2", content: "Evidence Fields", id: "evidence-fields" },
        { type: "paragraph", content: "Each finding includes evidence to help you reproduce and verify the issue:" },
        {
          type: "table", headers: ["Field", "Description"], rows: [
            ["URL", "The exact endpoint where the vulnerability was found"],
            ["Parameter", "The input parameter exploited (e.g., ?id=, Authorization header)"],
            ["Payload", "The probe payload that triggered the vulnerability"],
            ["Response", "Snippet of the server response that confirmed the issue"],
            ["CWE ID", "Common Weakness Enumeration identifier"],
            ["OWASP Category", "Which OWASP Top 10 category this maps to"],
          ]
        },
        { type: "heading2", content: "Attack Path Findings", id: "attack-paths" },
        { type: "paragraph", content: "Some findings are grouped into attack paths — multi-step exploit chains that show how an attacker could combine individual vulnerabilities to achieve a higher-impact breach. Pay special attention to findings that appear in attack paths as they have compounded real-world risk." },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2: INSTALLATION & SETUP
// ─────────────────────────────────────────────────────────────────────────────

const installationSetup: DocSection = {
  id: "installation-setup",
  title: "Installation & Setup",
  icon: "settings",
  description: "Account creation, configuration, and API keys.",
  articles: [
    {
      slug: "account-setup",
      title: "Account Creation & Login",
      description: "How to create your Quantara account and sign in for the first time.",
      category: "Installation & Setup",
      estimatedRead: 3,
      lastUpdated: "2026-02-01",
      content: [
        { type: "step", number: 1, title: "Visit the sign-up page", content: "Navigate to the Quantara web app and click 'Access Portal' or visit /login directly." },
        { type: "step", number: 2, title: "Choose your sign-in method", content: "You can register with an email and password, or use Google Single Sign-On (SSO) for faster access." },
        { type: "step", number: 3, title: "Verify your email", content: "If registering with email, check your inbox for a verification link. Click it to activate your account. The link expires after 24 hours." },
        { type: "step", number: 4, title: "Accept terms of service", content: "On first login, you'll be prompted to review and accept Quantara's Terms of Service and Privacy Policy." },
        { type: "step", number: 5, title: "Access the dashboard", content: "After verification, you're taken directly to your dashboard. Your account starts on the Free tier." },
        { type: "note", content: "If you don't receive the verification email within 5 minutes, check your spam folder. You can request a new verification email from the login page." },
        { type: "heading2", content: "Account Tiers", id: "account-tiers" },
        {
          type: "table", headers: ["Tier", "Scans/Month", "Modules", "AI Copilot", "Support"], rows: [
            ["Free", "10", "All", "Full", "Community"],
            ["Pro", "200", "All", "Full", "Priority Email"],
            ["Elite", "Unlimited", "All + Custom", "Full + API", "Dedicated CSM"],
          ]
        },
      ],
    },
    {
      slug: "project-setup",
      title: "Project Setup",
      description: "Organize your targets and configure scan projects.",
      category: "Installation & Setup",
      estimatedRead: 4,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara organizes scans under your account. Each scan is associated with a target URL and stored in your scan history for comparison and trending." },
        { type: "heading2", content: "Defining a Target", id: "defining-a-target" },
        { type: "paragraph", content: "A target is any web application URL you have authorization to scan. Quantara accepts:" },
        {
          type: "list", items: [
            "Full URLs: https://app.example.com",
            "Sub-paths: https://app.example.com/api/v1",
            "IP addresses: https://192.168.1.100",
            "Localhost (for local dev): http://localhost:3000",
          ]
        },
        { type: "warning", title: "Authorization Required", content: "Only scan systems you own or have explicit written permission to test. Quantara logs all scan targets. Unauthorized scans violate our ToS and applicable laws." },
        { type: "heading2", content: "Scan Depth Options", id: "scan-depth" },
        {
          type: "table", headers: ["Depth", "Description", "Recommended For"], rows: [
            ["Quick", "Fast sweep of common vulnerabilities", "CI/CD pipelines, quick checks"],
            ["Standard", "Balanced coverage vs. speed", "Regular security reviews"],
            ["Deep", "Thorough multi-pass scanning", "Pre-release security assessments"],
            ["Custom", "Configure individual modules", "Expert users, targeted testing"],
          ]
        },
      ],
    },
    {
      slug: "scanner-configuration",
      title: "Scanner Configuration",
      description: "Configure scan modules, rate limits, and advanced options.",
      category: "Installation & Setup",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara's scanner is highly configurable. Understanding the available options lets you tune scans for your specific environment." },
        { type: "heading2", content: "Module Selection", id: "module-selection" },
        { type: "paragraph", content: "By default, all available modules run in a standard scan. You can enable or disable specific modules to focus on areas of concern or exclude irrelevant checks." },
        { type: "heading2", content: "Rate Limiting", id: "rate-limiting" },
        { type: "paragraph", content: "The Safe Scan Guard controls how aggressively Quantara probes your target. Adjust rate limits to prevent impacting production system performance." },
        {
          type: "table", headers: ["Setting", "Default", "Description"], rows: [
            ["Requests/Second", "10", "Maximum HTTP requests per second"],
            ["Concurrent Connections", "5", "Parallel connections to the target"],
            ["Request Timeout", "30s", "Timeout per individual request"],
            ["Max Retries", "3", "Retry count for failed requests"],
          ]
        },
        { type: "tip", title: "Production Scanning", content: "When scanning production systems, use conservative rate limits (2–3 req/s) and schedule scans during off-peak hours to minimize performance impact." },
        { type: "heading2", content: "Authentication Configuration", id: "auth-config" },
        { type: "paragraph", content: "To scan authenticated endpoints, configure session credentials. Quantara supports:" },
        {
          type: "list", items: [
            "Cookie-based session authentication",
            "Bearer token (JWT / OAuth)",
            "Basic authentication (username/password)",
            "Custom HTTP headers",
          ]
        },
        {
          type: "code", language: "json", filename: "auth-config-example.json", content: `{
  "auth": {
    "type": "bearer",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "header": "Authorization"
  }
}` },
      ],
    },
    {
      slug: "api-key-setup",
      title: "API Key Management",
      description: "Generate and manage API keys for programmatic access and CI/CD integration.",
      category: "Installation & Setup",
      estimatedRead: 4,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara provides a REST API for programmatic scan management. API keys authenticate your requests without requiring interactive login." },
        { type: "heading2", content: "Generating an API Key", id: "generating-api-key" },
        { type: "step", number: 1, title: "Navigate to Settings", content: "Click 'Settings' in the sidebar navigation." },
        { type: "step", number: 2, title: "Select API Keys tab", content: "Find the 'API Keys' section in your account settings." },
        { type: "step", number: 3, title: "Click Generate New Key", content: "Give your key a descriptive name (e.g., 'CI/CD Pipeline', 'Monitoring Bot')." },
        { type: "step", number: 4, title: "Copy and store securely", content: "The full API key is only shown once. Store it in a secrets manager or environment variable immediately." },
        { type: "warning", content: "Never commit API keys to source control. Use environment variables or a secrets manager (e.g., GitHub Secrets, HashiCorp Vault)." },
        { type: "heading2", content: "Using the API", id: "using-the-api" },
        {
          type: "code", language: "bash", filename: "api-example.sh", content: `# Start a scan via API
curl -X POST https://api.quantara.io/api/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target_url": "https://app.example.com", "scan_depth": "standard"}'

# Get scan status
curl https://api.quantara.io/api/v1/scan/SCAN_ID \\
  -H "Authorization: Bearer YOUR_API_KEY"` },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3: SCANNER MODULES
// ─────────────────────────────────────────────────────────────────────────────

const scannerModules: DocSection = {
  id: "scanner-modules",
  title: "Scanner Modules",
  icon: "scan",
  description: "Deep documentation for every scanner module.",
  articles: [
    {
      slug: "security-scanner",
      title: "Security Scanner",
      description: "Complete coverage of the OWASP Top 10 most critical web security risks.",
      category: "Scanner Modules",
      estimatedRead: 8,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Security Scanner is Quantara's flagship module. It systematically tests your web application against all critical security categories including the industry-standard classification of the most critical web application security risks." },
        { type: "heading2", content: "OWASP Top 10 Coverage", id: "owasp-coverage" },
        {
          type: "table", headers: ["#", "Category", "What We Detect"], rows: [
            ["A01", "Broken Access Control", "IDOR, privilege escalation, missing auth checks"],
            ["A02", "Cryptographic Failures", "Weak ciphers, unencrypted data, insecure cookies"],
            ["A03", "Injection", "SQL, OS command, LDAP, NoSQL, SSTI injection"],
            ["A04", "Insecure Design", "Missing rate limits, logic flaws, insecure flows"],
            ["A05", "Security Misconfiguration", "Default creds, verbose errors, exposed configs"],
            ["A06", "Vulnerable Components", "Outdated JS libraries with known CVEs"],
            ["A07", "Auth & Session Failures", "Weak passwords, session fixation, JWT issues"],
            ["A08", "Software & Data Integrity", "Unsigned updates, CI/CD tampering"],
            ["A09", "Security Logging Failures", "Missing audit logs, unmonitored endpoints"],
            ["A10", "SSRF", "Server-side request forgery, internal service access"],
          ]
        },
        { type: "heading2", content: "How It Works", id: "how-it-works" },
        {
          type: "ordered-list", items: [
            "Detect: Crawl target application, enumerate endpoints and parameters",
            "Analyze: Apply OWASP-mapped detection rules to each endpoint",
            "Verify: AI Exploit Verifier confirms positive detections",
            "Score: Risk score computed from finding severity distribution",
            "Recommend: AI Copilot generates targeted remediation steps",
          ]
        },
        { type: "heading2", content: "How to Run", id: "how-to-run" },
        { type: "step", number: 1, title: "Open the Scanner", content: "Navigate to Dashboard → Security Scanner in the sidebar." },
        { type: "step", number: 2, title: "Enter target URL", content: "Input the full URL of your web application." },
        { type: "step", number: 3, title: "Select scan profile", content: "Choose 'Full Security Sweep' for comprehensive coverage." },
        { type: "step", number: 4, title: "Start scan", content: "Click 'Start Scan'. Findings begin streaming immediately." },
        { type: "image", src: "/OWASP Scanner Screenshot.png", caption: "Security Scanner in Action", label: "Scanner" },
        { type: "heading2", content: "Best Practices", id: "best-practices" },
        {
          type: "list", items: [
            "Run full Security sweeps before every major release",
            "Schedule automated weekly scans in off-peak hours",
            "Always scan both authenticated and unauthenticated surfaces",
            "Compare Risk Score trends across scan history to track improvement",
          ]
        },
      ],
    },
    {
      slug: "injection-scanner",
      title: "Injection Attack Scanner",
      description: "Detects SQL, command, LDAP, NoSQL, and template injection vulnerabilities.",
      category: "Scanner Modules",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Injection attacks remain one of the most dangerous and prevalent vulnerability classes. The Injection Scanner probes every user-controlled input for injection points across multiple attack vectors." },
        { type: "heading2", content: "Attack Vectors Covered", id: "attack-vectors" },
        {
          type: "list", items: [
            "SQL Injection (classic, blind, time-based, error-based)",
            "OS Command Injection",
            "LDAP Injection",
            "NoSQL Injection (MongoDB operators)",
            "Server-Side Template Injection (SSTI)",
            "XML External Entity (XXE)",
            "XPath Injection",
          ]
        },
        { type: "heading2", content: "Detection Logic", id: "detection-logic" },
        { type: "paragraph", content: "For each endpoint parameter, the scanner systematically injects test payloads and analyzes responses for:" },
        {
          type: "list", items: [
            "Database error messages (SQL syntax errors, stack traces)",
            "Behavioral differences between control and injected requests",
            "Time delays indicating blind injection (time-based)",
            "Reflected payload content in responses",
            "Unexpected HTTP status codes or response sizes",
          ]
        },
        { type: "heading2", content: "Example Findings", id: "example-findings" },
        { type: "note", title: "SQL Injection Example", content: "Parameter: id=1' OR '1'='1 | Response contains MySQL error: 'You have an error in your SQL syntax' | Severity: Critical | Confidence: 97%" },
        { type: "heading2", content: "Remediation Guidance", id: "remediation" },
        { type: "paragraph", content: "Injection vulnerabilities are almost always preventable. Key mitigations:" },
        {
          type: "ordered-list", items: [
            "Use parameterized queries / prepared statements (never string concatenation)",
            "Apply input validation and allowlist filtering at every boundary",
            "Implement least-privilege database accounts",
            "Use an ORM that handles escaping automatically",
            "Enable detailed error logging server-side but suppress from client responses",
          ]
        },
        {
          type: "code", language: "python", filename: "secure-query.py", content: `# VULNERABLE - never do this
query = f"SELECT * FROM users WHERE id = {user_input}"

# SECURE - use parameterized queries
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))` },
      ],
    },
    {
      slug: "misconfiguration-engine",
      title: "Security Misconfiguration Engine",
      description: "Detects misconfigured servers, headers, CORS policies, and exposed admin interfaces.",
      category: "Scanner Modules",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Security Misconfiguration is the #1 OWASP category by prevalence. Small configuration mistakes can expose your entire application. This module systematically audits your application's security posture at the configuration layer." },
        { type: "heading2", content: "What It Checks", id: "checks" },
        {
          type: "table", headers: ["Category", "Examples"], rows: [
            ["HTTP Security Headers", "Missing HSTS, X-Frame-Options, CSP, X-Content-Type-Options"],
            ["CORS Policy", "Wildcard origins, credentials with wildcard, overly permissive policies"],
            ["SSL/TLS Configuration", "Weak cipher suites, expired certificates, SSLv3/TLS1.0"],
            ["Server Disclosure", "Server version banners, technology headers, error stack traces"],
            ["Directory Listing", "Enabled directory browsing, backup files exposure"],
            ["Admin Panel Exposure", "Publicly accessible /admin, /phpmyadmin, /.env, /config"],
            ["Default Credentials", "Default admin/admin, known default passwords for common systems"],
            ["Debug Mode", "Debug endpoints active in production, verbose error pages"],
          ]
        },
        { type: "heading2", content: "Recommended Security Headers", id: "security-headers" },
        {
          type: "code", language: "nginx", filename: "security-headers.conf", content: `# Add these to your nginx/server config
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-RANDOM';";
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";` },
      ],
    },
    {
      slug: "endpoint-extractor",
      title: "Endpoint Discovery",
      description: "Automatically discovers hidden endpoints, API routes, and exposed resources.",
      category: "Scanner Modules",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Endpoint Extractor maps the full attack surface of your application. It discovers routes, API endpoints, and resources that may not be intentionally exposed — providing the foundation for comprehensive security testing." },
        { type: "heading2", content: "Discovery Techniques", id: "discovery-techniques" },
        {
          type: "list", items: [
            "Web crawling — following links and JavaScript references",
            "robots.txt and sitemap.xml parsing",
            "Common path fuzzing with a curated wordlist (10,000+ entries)",
            "JavaScript source analysis for hardcoded API paths",
            "API specification discovery (OpenAPI/Swagger, GraphQL introspection)",
            "Backup file detection (.bak, .old, .zip, .tar.gz)",
            "Version control exposure (.git, .svn, .hg directories)",
          ]
        },
        { type: "heading2", content: "Output", id: "output" },
        { type: "paragraph", content: "The Endpoint Extractor feeds discovered endpoints to all other scanner modules automatically, ensuring complete coverage of your attack surface." },
        { type: "image", src: "/Endpoint Map Screenshot.png", caption: "Endpoint Map Visualization", label: "Discovery" },
        { type: "tip", content: "The endpoint discovery results are also available via the Coverage API endpoint: GET /api/v1/scan/{id}/coverage" },
      ],
    },
    {
      slug: "frontend-js-analyzer",
      title: "Frontend JavaScript Analyzer",
      description: "Analyzes client-side JavaScript for secrets, vulnerable libraries, and unsafe patterns.",
      category: "Scanner Modules",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Modern web apps rely heavily on client-side JavaScript. This module analyzes loaded scripts for security issues that are invisible to traditional scanners." },
        { type: "heading2", content: "What It Detects", id: "detects" },
        {
          type: "list", items: [
            "Hardcoded secrets — API keys, tokens, passwords embedded in JS",
            "Vulnerable npm packages — libraries with known CVEs",
            "Unsafe patterns — eval(), innerHTML, document.write()",
            "Exposed API endpoints in frontend code",
            "DOM-based XSS sinks and sources",
            "PostMessage misuse allowing XSS",
            "Prototype pollution vulnerabilities",
            "Sensitive data in localStorage or sessionStorage",
          ]
        },
        { type: "warning", title: "Frontend Secrets are Public", content: "Any secret embedded in client-side JavaScript is visible to anyone with browser DevTools. Rotate any secrets found in frontend code immediately." },
        { type: "heading2", content: "Example Finding", id: "example" },
        {
          type: "code", language: "javascript", filename: "vulnerable-example.js", content: `// CRITICAL: API key exposed in frontend bundle
const STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"; // Never hardcode live keys

// HIGH: Unsafe DOM manipulation (XSS risk)
document.getElementById('output').innerHTML = userInput; // Use textContent instead` },
      ],
    },
    {
      slug: "exploit-verifier",
      title: "Exploit Verification Engine",
      description: "AI-powered proof-based system that confirms whether vulnerabilities are genuinely exploitable.",
      category: "Scanner Modules",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Most scanners report hundreds of potential findings, leaving security teams drowning in false positives. The Exploit Verification Engine changes this — it uses a multi-stage AI reasoning pipeline to confirm whether each finding is genuinely exploitable before surfacing it." },
        { type: "heading2", content: "Verification Pipeline", id: "pipeline" },
        {
          type: "ordered-list", items: [
            "Detect — Scanner module identifies potential vulnerability",
            "Plan — AI analyzes detection context and selects verification strategy",
            "Verify — Active proof attempt using safe exploit payloads",
            "Prove — Collect concrete evidence (server response, behavioral change)",
            "Score — Assign confidence score (0–100%) and severity rating",
          ]
        },
        { type: "image", src: "/Verification Flow Diagram.png", caption: "Exploit Verification Flow", label: "AI Verification" },
        { type: "heading2", content: "Confidence Scoring", id: "confidence-scoring" },
        {
          type: "table", headers: ["Score", "Status", "Meaning"], rows: [
            ["90–100%", "Verified", "AI confirmed exploitability with concrete proof"],
            ["70–89%", "High Confidence", "Strong evidence, minimal doubt"],
            ["50–69%", "Medium Confidence", "Possible vulnerability, warrants manual review"],
            ["< 50%", "Low Confidence", "Likely false positive — informational only"],
          ]
        },
        { type: "note", content: "Only Verified and High Confidence findings contribute to your Risk Score calculation, reducing noise from unconfirmed detections." },
        { type: "heading2", content: "SSE Events", id: "sse-events" },
        { type: "paragraph", content: "Verification progress streams in real-time. You'll see verification_success events in the live scan feed when the AI confirms a finding." },
      ],
    },
    {
      slug: "attack-path-analyzer",
      title: "Attack Path Analyzer",
      description: "Visualizes multi-step exploit chains showing how vulnerabilities combine into critical breaches.",
      category: "Scanner Modules",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Individual vulnerabilities rarely exist in isolation. A medium-severity misconfiguration combined with a low-severity information disclosure can become a critical breach. The Attack Path Analyzer maps these chains." },
        { type: "heading2", content: "How Attack Paths Work", id: "how-it-works" },
        { type: "paragraph", content: "After all scanner modules complete, the analyzer:" },
        {
          type: "ordered-list", items: [
            "Ingests all confirmed findings as graph nodes",
            "Identifies relationships between findings (e.g., endpoint A exposes credentials used in endpoint B)",
            "Constructs multi-hop attack chains using graph traversal",
            "Simulates breach scenarios based on real attacker TTPs (tactics, techniques, procedures)",
            "Calculates chain-level severity (often higher than individual finding severity)",
          ]
        },
        { type: "image", src: "/Attack Graph Screenshot.png", caption: "Attack Graph Visualization", label: "Attack Visualization" },
        { type: "heading2", content: "Reading the Attack Graph", id: "reading" },
        { type: "paragraph", content: "Each node in the graph represents a finding. Edges represent logical connections between findings. Red nodes are critical; orange are high severity. The 'blast radius' metric estimates the maximum damage achievable by following a path." },
        { type: "heading2", content: "Attack Graph API", id: "api" },
        {
          type: "code", language: "bash", content: `# Retrieve attack graph data
GET /api/v1/scan/{scan_id}/attack-graph

# Response includes:
# - nodes: array of findings
# - edges: connections between findings
# - paths: complete attack chains
# - breach_scenarios: simulated breach outcomes` },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4: AI COPILOT
// ─────────────────────────────────────────────────────────────────────────────

const aiCopilot: DocSection = {
  id: "ai-copilot",
  title: "AI Copilot",
  icon: "bot",
  description: "AI-powered security guidance and remediation.",
  articles: [
    {
      slug: "ai-copilot-overview",
      title: "What AI Copilot Does",
      description: "Understand the capabilities of Quantara's AI Security Copilot.",
      category: "AI Copilot",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The AI Security Copilot is your intelligent security partner inside Quantara. It combines deep knowledge of vulnerability classes, remediation techniques, and your specific scan results to provide contextually accurate, actionable guidance." },
        { type: "image", src: "/AI Copilot Screenshot.png", caption: "AI Copilot Interface", label: "Copilot" },
        { type: "heading2", content: "Core Capabilities", id: "capabilities" },
        {
          type: "list", items: [
            "Vulnerability explanation — translate technical findings into plain English",
            "Severity assessment — explain why a finding is Critical vs. Medium",
            "Remediation guidance — step-by-step fix instructions with code examples",
            "Attack reasoning — explain how an attacker would exploit a finding",
            "Attack path walkthrough — narrate multi-step breach scenarios",
            "Patch generation — suggest secure code replacements",
            "Compliance mapping — map findings to PCI-DSS, HIPAA, SOC 2 requirements",
          ]
        },
        { type: "heading2", content: "Accessing AI Copilot", id: "accessing" },
        { type: "paragraph", content: "AI Copilot is accessible from multiple locations in the dashboard:" },
        {
          type: "list", items: [
            "Finding detail panel — click any finding to open its AI analysis",
            "Floating Copilot panel — persistent chat interface on the right side of the scanner",
            "Attack path view — click any path to get AI narrative of the breach",
          ]
        },
        { type: "note", content: "AI Copilot responses are context-aware. When you open a finding, the Copilot automatically loads context about that specific vulnerability and your application." },
      ],
    },
    {
      slug: "ai-copilot-prompts",
      title: "Example Prompts & Workflows",
      description: "Proven prompt patterns for getting the most out of AI Copilot.",
      category: "AI Copilot",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "AI Copilot responds best to specific, contextual questions. Here are proven prompt patterns for common security investigation workflows." },
        { type: "heading2", content: "Understanding a Finding", id: "understanding" },
        {
          type: "list", items: [
            '"Explain this SQL injection vulnerability in simple terms"',
            '"Why is this finding rated Critical instead of High?"',
            '"What data could an attacker access by exploiting this?"',
            '"Show me a proof-of-concept for this vulnerability"',
          ]
        },
        { type: "heading2", content: "Remediation Guidance", id: "remediation" },
        {
          type: "list", items: [
            '"How do I fix this SQL injection in Python/FastAPI?"',
            '"Generate a code patch for this XSS vulnerability"',
            '"What security headers should I add to fix this misconfiguration?"',
            '"Give me a step-by-step remediation plan for all Critical findings"',
          ]
        },
        { type: "heading2", content: "Attack Path Investigation", id: "attack-investigation" },
        {
          type: "list", items: [
            '"Walk me through this attack path from start to finish"',
            '"Which vulnerability in this chain should I fix first?"',
            '"What is the maximum impact if this attack path is fully exploited?"',
            '"How would an attacker move laterally after exploiting this?"',
          ]
        },
        { type: "heading2", content: "Risk Assessment", id: "risk-assessment" },
        {
          type: "list", items: [
            '"Summarize the top 3 risks from this scan"',
            '"Is my application safe to deploy given these findings?"',
            '"How does my risk score compare to industry benchmarks?"',
            '"Map these findings to PCI-DSS requirements"',
          ]
        },
        { type: "tip", content: "AI Copilot retains context within a scan session. You can ask follow-up questions and it will remember previous context in the conversation." },
      ],
    },
    {
      slug: "ai-confidence-scoring",
      title: "AI Confidence & Reasoning",
      description: "How Quantara's AI calculates confidence scores and makes decisions.",
      category: "AI Copilot",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Quantara's AI systems are built on a transparent reasoning framework. Understanding how confidence is calculated helps you calibrate trust in findings and make better security decisions." },
        { type: "heading2", content: "Confidence Score Calculation", id: "calculation" },
        { type: "paragraph", content: "The AI Exploit Verifier computes confidence using:" },
        {
          type: "list", items: [
            "Exploit evidence quality — strength of server response proving exploitability",
            "Payload reliability — how consistently the payload triggers the vulnerability",
            "Parameter sensitivity — whether the input was truly user-controlled",
            "Response analysis — AI analysis of differential behavior",
            "Historical pattern matching — similarity to known confirmed vulnerabilities",
          ]
        },
        { type: "heading2", content: "AI Decision Engine", id: "decision-engine" },
        { type: "paragraph", content: "The Attack Decision Engine determines which modules to run next based on intermediate findings. It prioritizes attack vectors based on:" },
        {
          type: "list", items: [
            "Current findings and their severity",
            "Target technology stack (inferred from headers/responses)",
            "Attack path potential — does this module extend existing chains?",
            "Coverage gaps — areas not yet assessed",
            "Time budget remaining",
          ]
        },
        { type: "note", content: "The AI Decision Engine streams its reasoning to your dashboard via ai_decision SSE events, so you can follow its logic in real-time." },
        { type: "heading2", content: "Transparency & Limitations", id: "limitations" },
        { type: "paragraph", content: "Quantara's AI is designed to augment human security expertise, not replace it. False negatives are possible — AI cannot guarantee 100% coverage. Always combine automated scanning with manual security review for critical systems." },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5: DASHBOARD GUIDE
// ─────────────────────────────────────────────────────────────────────────────

const dashboardGuide: DocSection = {
  id: "dashboard-guide",
  title: "Dashboard Guide",
  icon: "layout",
  description: "Every panel, metric, and visualization explained.",
  articles: [
    {
      slug: "security-metrics",
      title: "Security Metrics & Risk Score",
      description: "How risk scores are calculated and how to interpret security metrics.",
      category: "Dashboard Guide",
      estimatedRead: 5,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Risk Score and security metrics cards give you an instant health check of your application's security posture. Understanding how they're calculated helps you track improvement accurately." },
        { type: "heading2", content: "Risk Score Formula", id: "formula" },
        { type: "paragraph", content: "The Risk Score (0–100, higher = safer) is calculated using:" },
        {
          type: "code", language: "python", content: `# Simplified risk score calculation
def compute_risk_score(severity_counts, coverage_pct, confidence_avg):
    # Severity deductions (from 100)
    critical_deduction = severity_counts.get('critical', 0) * 25
    high_deduction = severity_counts.get('high', 0) * 12
    medium_deduction = severity_counts.get('medium', 0) * 5
    low_deduction = severity_counts.get('low', 0) * 1

    base_score = max(0, 100 - critical_deduction - high_deduction
                          - medium_deduction - low_deduction)

    # Coverage multiplier: low coverage = less reliable score
    coverage_factor = (coverage_pct / 100) ** 0.5

    return round(base_score * coverage_factor)` },
        { type: "heading2", content: "Scan Confidence Levels", id: "confidence-levels" },
        {
          type: "table", headers: ["Confidence", "Coverage %", "Meaning"], rows: [
            ["CONCLUSIVE", "> 75%", "High scan coverage, reliable score"],
            ["LIKELY", "50–75%", "Good coverage, score is representative"],
            ["POSSIBLE", "25–50%", "Moderate coverage, more scanning recommended"],
            ["INCONCLUSIVE", "< 25%", "Low coverage, score may not reflect true risk"],
          ]
        },
        { type: "note", content: "A score of 100 with INCONCLUSIVE confidence means the scanner ran but found no issues in the limited surface area it covered — not that the application is secure." },
      ],
    },
    {
      slug: "attack-graph",
      title: "Attack Graph Visualization",
      description: "Understanding the visual attack graph and breach simulation results.",
      category: "Dashboard Guide",
      estimatedRead: 4,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Attack Graph is a visual representation of how individual vulnerabilities connect into exploit chains. It transforms raw finding lists into actionable breach narrative." },
        { type: "image", src: "/Attack Graph Screenshot.png", caption: "Attack Graph Panel", label: "Attack Analysis" },
        { type: "heading2", content: "Graph Elements", id: "graph-elements" },
        {
          type: "table", headers: ["Element", "Meaning"], rows: [
            ["Red node", "Critical severity finding"],
            ["Orange node", "High severity finding"],
            ["Yellow node", "Medium severity finding"],
            ["Green node", "Low/Info finding"],
            ["Solid edge", "Direct exploit chain connection"],
            ["Dashed edge", "Indirect or conditional connection"],
            ["Highlighted path", "Selected attack path being examined"],
          ]
        },
        { type: "heading2", content: "Breach Scenarios", id: "breach-scenarios" },
        { type: "paragraph", content: "The Attack Path Analyzer generates breach scenarios — narratives describing how a realistic attacker would combine vulnerabilities to achieve specific objectives (data exfiltration, RCE, privilege escalation)." },
        { type: "tip", content: "Click any attack path in the graph to ask AI Copilot to walk you through the full scenario." },
      ],
    },
    {
      slug: "findings-panel",
      title: "Findings Panel",
      description: "How to navigate, filter, and act on findings in the dashboard.",
      category: "Dashboard Guide",
      estimatedRead: 4,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The Findings Panel is the primary interface for reviewing discovered vulnerabilities. It supports filtering, sorting, and direct AI analysis from a single view." },
        { type: "image", src: "/Findings Panel Screenshot.png", caption: "Findings Panel View", label: "Findings list" },
        { type: "heading2", content: "Filtering & Sorting", id: "filtering" },
        {
          type: "list", items: [
            "Filter by severity (Critical / High / Medium / Low / Info)",
            "Filter by OWASP category",
            "Filter by verification status (Verified / Unverified)",
            "Filter by scanner module",
            "Sort by severity, confidence, or discovery time",
            "Search by URL, parameter, or vulnerability type",
          ]
        },
        { type: "heading2", content: "Finding Detail View", id: "detail-view" },
        { type: "paragraph", content: "Click any finding to expand its full detail view, which includes:" },
        {
          type: "list", items: [
            "Full evidence — request/response pair that confirmed the vulnerability",
            "Technical explanation — what the vulnerability is and why it's dangerous",
            "AI Copilot analysis — automated remediation recommendation",
            "Related findings — other vulnerabilities in the same attack path",
            "CWE/CVE references — industry-standard vulnerability IDs",
            "OWASP reference link — direct link to OWASP documentation",
          ]
        },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6: TUTORIALS
// ─────────────────────────────────────────────────────────────────────────────

const tutorials: DocSection = {
  id: "tutorials",
  title: "Tutorials",
  icon: "graduation-cap",
  description: "Step-by-step guided workflows for common tasks.",
  articles: [
    {
      slug: "tutorial-first-scan",
      title: "Tutorial 1: Run Your First Scan",
      description: "Complete beginner walkthrough from account creation to first security findings.",
      category: "Tutorials",
      estimatedRead: 8,
      lastUpdated: "2026-02-01",
      content: [
        { type: "note", title: "Difficulty: Beginner", content: "This tutorial assumes no prior experience with security scanning. You'll have results in under 5 minutes." },
        { type: "heading2", content: "What You'll Learn", id: "what-youll-learn" },
        {
          type: "list", items: [
            "How to configure your first scan",
            "How to monitor real-time findings",
            "How to read severity levels",
            "How to use AI Copilot on a finding",
          ]
        },
        { type: "step", number: 1, title: "Create a free account", content: "Go to the Quantara web app. Click 'Access Portal', then 'Create Account'. Use your email or Google SSO. Verify your email if prompted." },
        { type: "step", number: 2, title: "Choose a test target", content: "For learning, use a deliberately vulnerable practice application like OWASP Juice Shop (https://juice-shop.herokuapp.com) or enter your own test environment URL." },
        { type: "step", number: 3, title: "Open the scanner", content: "After logging in, click 'OWASP Scanner' in the left sidebar." },
        { type: "step", number: 4, title: "Enter the URL and start", content: "Paste your target URL into the scanner input field. Leave all other settings at default. Click 'Start Scan'." },
        { type: "image", src: "/Scanner Config Screenshot.png", caption: "Scan Configuration Screen", label: "Step 4" },
        { type: "step", number: 5, title: "Watch the scan unfold", content: "Findings begin appearing in the panel below. Each finding shows severity, type, and confidence score. The progress bar shows module completion status." },
        { type: "step", number: 6, title: "Investigate a finding", content: "Click any finding to expand its details. Review the evidence, then click 'Ask AI Copilot' to get a plain-English explanation and fix recommendation." },
        { type: "step", number: 7, title: "Review your risk score", content: "When the scan completes, your Risk Score updates in the metrics panel. Check the Attack Graph to see if any vulnerabilities form exploit chains." },
        { type: "tip", content: "Save your scan results to your History tab by bookmarking the scan URL. You can compare future scans against this baseline." },
      ],
    },
    {
      slug: "tutorial-analyze",
      title: "Tutorial 2: Analyze Vulnerabilities",
      description: "Learn to triage findings, assess risk, and prioritize remediation efforts.",
      category: "Tutorials",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "note", title: "Difficulty: Intermediate", content: "This tutorial assumes you've completed Tutorial 1 and have scan results available." },
        { type: "heading2", content: "Triage Workflow", id: "triage-workflow" },
        { type: "paragraph", content: "Security triage is the process of sorting findings by actual risk to your business, not just technical severity. Follow this workflow for effective prioritization:" },
        { type: "step", number: 1, title: "Start with Critical findings", content: "Open the Findings panel and filter to Critical severity only. These are your immediate priorities — address them before any release." },
        { type: "step", number: 2, title: "Check verification status", content: "Look at the confidence score for each Critical finding. Findings with 90%+ confidence are verified exploitable. Start with these." },
        { type: "step", number: 3, title: "Review attack paths", content: "Open the Attack Graph. Any finding that appears in an attack chain has compounded risk — it may enable further exploitation. Prioritize these even if individually rated Medium." },
        { type: "step", number: 4, title: "Use AI Copilot for context", content: "For each high-priority finding, ask AI Copilot: 'What is the real-world impact of this vulnerability in our context?' This helps non-technical stakeholders understand urgency." },
        { type: "step", number: 5, title: "Build a remediation plan", content: "Ask AI Copilot: 'Give me a prioritized remediation plan for all Critical and High findings.' Use this output to create engineering tickets." },
        { type: "heading2", content: "False Positive Handling", id: "false-positives" },
        { type: "paragraph", content: "Low-confidence findings (below 50%) may be false positives. Before dismissing them:" },
        {
          type: "list", items: [
            "Review the evidence — is the proof convincing?",
            "Ask AI Copilot to verify: 'Is this likely a false positive and why?'",
            "Manually test the finding if in doubt",
            "If confirmed false positive, mark as 'Accepted Risk' with a justification note",
          ]
        },
      ],
    },
    {
      slug: "tutorial-ai-copilot",
      title: "Tutorial 3: Using AI Copilot",
      description: "Master AI-assisted security investigation and remediation workflows.",
      category: "Tutorials",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "note", title: "Difficulty: Intermediate", content: "Best experienced with an active scan containing at least 5 findings." },
        { type: "heading2", content: "Opening AI Copilot", id: "opening" },
        { type: "paragraph", content: "AI Copilot is accessible from the scanner page. Look for the chat icon panel on the right side of the scanner interface. It auto-loads context from your current scan." },
        { type: "step", number: 1, title: "Load a finding into Copilot", content: "Click any finding in the findings panel. The AI Copilot panel will automatically load context about that specific vulnerability." },
        { type: "step", number: 2, title: "Ask for an explanation", content: 'Type: "Explain this vulnerability to me as if I\'m a developer who has never seen this before." The Copilot will give a clear, jargon-free explanation.' },
        { type: "step", number: 3, title: "Request remediation code", content: 'Ask: "Show me the vulnerable code pattern and the secure replacement." The Copilot generates before/after code examples.' },
        { type: "step", number: 4, title: "Understand the attack chain", content: 'If the finding is part of an attack path, ask: "How would an attacker use this in combination with other findings?" Copilot narrates the full chain.' },
        { type: "step", number: 5, title: "Generate a ticket description", content: 'Ask: "Write a Jira ticket description for this vulnerability including severity, evidence, and remediation steps." Copy and paste directly into your issue tracker.' },
        { type: "tip", content: "AI Copilot remembers context within your session. You can reference earlier questions with 'Based on what we discussed earlier...' for multi-turn analysis." },
      ],
    },
    {
      slug: "tutorial-remediation",
      title: "Tutorial 4: Fixing Vulnerabilities",
      description: "The complete remediation lifecycle from finding to verified fix.",
      category: "Tutorials",
      estimatedRead: 8,
      lastUpdated: "2026-02-01",
      content: [
        { type: "note", title: "Difficulty: Intermediate", content: "Covers the full cycle from finding to verified fix, including re-scan verification." },
        { type: "heading2", content: "Remediation Lifecycle", id: "lifecycle" },
        {
          type: "ordered-list", items: [
            "Identify: Scan finds and verifies vulnerability",
            "Triage: Assess priority and business impact",
            "Investigate: Use AI Copilot to understand root cause",
            "Fix: Implement the remediation in your codebase",
            "Verify: Re-scan to confirm the vulnerability is resolved",
            "Document: Record the remediation for compliance purposes",
          ]
        },
        { type: "step", number: 1, title: "Understand the root cause", content: 'Ask AI Copilot: "What is the root cause of this vulnerability — not just the symptom?" Understanding the root cause prevents similar issues from reappearing.' },
        { type: "step", number: 2, title: "Get a fix recommendation", content: 'Ask: "Show me exactly how to fix this in [your language/framework]." AI Copilot generates framework-specific remediation code.' },
        { type: "step", number: 3, title: "Implement the fix", content: "Apply the remediation to your codebase. Test it locally before deploying. Commit with a message referencing the Quantara finding ID." },
        { type: "step", number: 4, title: "Deploy and re-scan", content: "Deploy your fix to the test environment, then run a new Quantara scan targeting the same URL. Watch the previously identified vulnerability disappear from results." },
        { type: "step", number: 5, title: "Compare Risk Score", content: "After the re-scan, compare your new Risk Score to the baseline from before your fix. Track improvement over time in the History tab." },
        { type: "tip", content: "Create a 'security fix' tag or label in your issue tracker to track the volume of security debt you're addressing over time." },
      ],
    },
    {
      slug: "tutorial-monitoring",
      title: "Tutorial 5: Continuous Monitoring",
      description: "Set up an enterprise continuous security monitoring workflow.",
      category: "Tutorials",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "note", title: "Difficulty: Advanced", content: "Designed for DevSecOps engineers building automated security pipelines." },
        { type: "heading2", content: "Continuous Security Philosophy", id: "philosophy" },
        { type: "paragraph", content: "Security is not a one-time audit — it's a continuous process. Every code change, dependency update, or configuration change can introduce new vulnerabilities. Quantara supports integration into your CI/CD pipeline for automatic security validation." },
        { type: "heading2", content: "CI/CD Integration", id: "ci-cd" },
        { type: "step", number: 1, title: "Generate an API key", content: "In Settings → API Keys, generate a CI/CD-specific key with a descriptive name. Store it in your CI/CD secrets vault." },
        { type: "step", number: 2, title: "Add scan step to pipeline", content: "Add a scan step after deployment to your staging environment:" },
        {
          type: "code", language: "yaml", filename: ".github/workflows/security.yml", content: `name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Quantara Scan
        run: |
          SCAN_ID=$(curl -s -X POST $QUANTARA_API/api/v1/scan \\
            -H "Authorization: Bearer $QUANTARA_API_KEY" \\
            -d '{"target_url": "\${{ env.STAGING_URL }}", "scan_depth": "quick"}' \\
            | jq -r '.scan_id')

          # Wait for completion
          sleep 60

          # Check risk score
          SCORE=$(curl -s $QUANTARA_API/api/v1/scan/$SCAN_ID \\
            -H "Authorization: Bearer $QUANTARA_API_KEY" \\
            | jq '.risk_score')

          # Fail if score below threshold
          if [ "$SCORE" -lt 70 ]; then
            echo "Security scan failed: Risk score $SCORE below threshold 70"
            exit 1
          fi` },
        { type: "step", number: 3, title: "Set quality gates", content: "Define minimum Risk Score thresholds. A common policy: block deployment if Risk Score < 70 or any Critical finding is present." },
        { type: "step", number: 4, title: "Schedule baseline scans", content: "Schedule weekly deep scans via API or cron. Compare against your historical baseline to detect regression or new attack surface." },
        { type: "tip", content: "For enterprise teams, configure Slack/PagerDuty webhooks to receive alerts when new Critical findings are discovered in scheduled scans." },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7: KNOWLEDGE BASE
// ─────────────────────────────────────────────────────────────────────────────

const knowledgeBase: DocSection = {
  id: "knowledge-base",
  title: "Knowledge Base",
  icon: "book",
  description: "Reference articles on common vulnerabilities and security concepts.",
  articles: [
    {
      slug: "owasp-top-10",
      title: "OWASP Top 10 Reference",
      description: "Complete reference guide to the OWASP Top 10 most critical web security risks.",
      category: "Knowledge Base",
      estimatedRead: 10,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "The OWASP Top 10 is the globally recognized standard for web application security risk classification, maintained by the Open Web Application Security Project (OWASP). Quantara's scanner is built around this framework." },
        {
          type: "table", headers: ["Rank", "Category", "Key Risk", "Prevalence"], rows: [
            ["A01:2021", "Broken Access Control", "IDOR, privilege escalation", "94% of apps tested"],
            ["A02:2021", "Cryptographic Failures", "Data exposure, weak encryption", "Very widespread"],
            ["A03:2021", "Injection", "SQL, OS, LDAP injection", "3rd most common"],
            ["A04:2021", "Insecure Design", "Missing security controls", "New in 2021"],
            ["A05:2021", "Security Misconfiguration", "Default configs, verbose errors", "90% of apps"],
            ["A06:2021", "Vulnerable & Outdated Components", "Known CVEs in libraries", "Very widespread"],
            ["A07:2021", "Identification & Authentication Failures", "Weak passwords, session issues", "Common"],
            ["A08:2021", "Software & Data Integrity Failures", "Unsigned updates, CI/CD", "New in 2021"],
            ["A09:2021", "Security Logging & Monitoring Failures", "Missing audit trails", "Very common"],
            ["A10:2021", "Server-Side Request Forgery (SSRF)", "Internal service access", "New in 2021"],
          ]
        },
        { type: "tip", content: "The OWASP Top 10 is updated periodically. Always reference the latest version at owasp.org/www-project-top-ten/" },
      ],
    },
    {
      slug: "sql-injection",
      title: "SQL Injection",
      description: "Deep dive into SQL injection: types, detection, and remediation.",
      category: "Knowledge Base",
      estimatedRead: 8,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "SQL Injection (SQLi) occurs when attacker-controlled data is interpreted as SQL code, allowing database manipulation. It remains one of the most critical and frequently exploited vulnerability classes." },
        { type: "heading2", content: "Types of SQL Injection", id: "types" },
        {
          type: "table", headers: ["Type", "How It Works", "Detection Method"], rows: [
            ["Classic / Error-based", "DB error messages reveal structure", "Error strings in response"],
            ["Union-based", "UNION SELECT appends extra data to results", "Column count probing"],
            ["Blind (Boolean)", "True/false conditions change response size/content", "Response differential"],
            ["Time-based Blind", "SLEEP() causes measurable delay", "Response time analysis"],
            ["Out-of-band", "Data exfiltrated via DNS/HTTP", "Network traffic analysis"],
          ]
        },
        { type: "heading2", content: "Real-World Impact", id: "impact" },
        {
          type: "list", items: [
            "Full database dump — all user credentials, PII, business data",
            "Authentication bypass — login as any user without a password",
            "Data modification or deletion",
            "In some cases: Remote Code Execution via stored procedures (xp_cmdshell)",
          ]
        },
        { type: "heading2", content: "Prevention", id: "prevention" },
        {
          type: "ordered-list", items: [
            "Use parameterized queries (prepared statements) — never concatenate user input into SQL",
            "Use an ORM that handles escaping (SQLAlchemy, Hibernate, ActiveRecord)",
            "Validate and sanitize all user inputs",
            "Apply least-privilege to database accounts — no DROP/ALTER permissions for app user",
            "Enable SQL query logging for anomaly detection",
            "Use a WAF as an additional layer (not a substitute for code fixes)",
          ]
        },
        {
          type: "code", language: "python", content: `# VULNERABLE
query = f"SELECT * FROM users WHERE username = '{username}'"

# SECURE - Parameterized query
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))

# SECURE - ORM approach (SQLAlchemy)
user = db.query(User).filter(User.username == username).first()` },
      ],
    },
    {
      slug: "xss",
      title: "Cross-Site Scripting (XSS)",
      description: "Understanding XSS types, attack scenarios, and secure coding practices.",
      category: "Knowledge Base",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. It's one of the most common web vulnerabilities and can lead to session hijacking, credential theft, and malware distribution." },
        { type: "heading2", content: "XSS Types", id: "types" },
        {
          type: "table", headers: ["Type", "Persistence", "Example Scenario"], rows: [
            ["Reflected", "Non-persistent", "Malicious link containing script in URL parameter"],
            ["Stored", "Persistent", "Script stored in database, executed for every viewer"],
            ["DOM-based", "Client-side", "Script injected via JavaScript DOM manipulation"],
          ]
        },
        { type: "heading2", content: "Attack Scenarios", id: "attack-scenarios" },
        {
          type: "list", items: [
            "Session hijacking — steal authenticated session cookies",
            "Credential harvesting — replace login form to capture passwords",
            "Keylogging — record every keystroke on the page",
            "Drive-by malware — redirect users to malware download",
            "DOM manipulation — alter page content for phishing",
          ]
        },
        { type: "heading2", content: "Prevention", id: "prevention" },
        {
          type: "ordered-list", items: [
            "Output encode all user-controlled data before rendering in HTML",
            "Use textContent instead of innerHTML for DOM manipulation",
            "Implement a strong Content-Security-Policy (CSP) header",
            "Validate and sanitize input on server side",
            "Use modern frameworks (React, Vue, Angular) which escape by default",
            "Set HttpOnly flag on session cookies to prevent script access",
          ]
        },
        {
          type: "code", language: "javascript", content: `// VULNERABLE - innerHTML with user data
element.innerHTML = userInput;

// SECURE - use textContent
element.textContent = userInput;

// SECURE - DOMPurify for HTML content that needs to preserve formatting
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);` },
      ],
    },
    {
      slug: "auth-vulnerabilities",
      title: "Authentication Vulnerabilities",
      description: "Common authentication and session management failures and how to fix them.",
      category: "Knowledge Base",
      estimatedRead: 7,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Authentication failures are rated A07 in OWASP Top 10. Weak authentication allows attackers to assume other users' identities, including administrators." },
        { type: "heading2", content: "Common Authentication Flaws", id: "common-flaws" },
        {
          type: "list", items: [
            "Weak password policies — allowing short, common, or breached passwords",
            "Missing brute-force protection — unlimited login attempts",
            "Insecure password reset — predictable tokens, no expiration",
            "Session fixation — attacker-controlled session IDs",
            "Missing logout — sessions not invalidated server-side",
            "Insecure 'Remember Me' — persistent tokens in plaintext",
            "JWT vulnerabilities — algorithm confusion, weak secrets, none-algorithm",
            "Default credentials — shipped without forced credential change",
          ]
        },
        { type: "heading2", content: "JWT Security", id: "jwt-security" },
        { type: "paragraph", content: "JWTs are widely used but frequently misconfigured:" },
        {
          type: "code", language: "python", content: `# VULNERABLE - accepting 'none' algorithm
jwt.decode(token, options={"verify_signature": False})

# VULNERABLE - weak secret
SECRET = "password123"

# SECURE - strong secret, explicit algorithm
import secrets
SECRET = secrets.token_hex(32)  # 256-bit secret
payload = jwt.decode(token, SECRET, algorithms=["HS256"])` },
        { type: "heading2", content: "Best Practices", id: "best-practices" },
        {
          type: "ordered-list", items: [
            "Enforce strong password policy (min 12 chars, breach database check)",
            "Implement MFA for all accounts, especially privileged ones",
            "Use account lockout after 5–10 failed attempts + CAPTCHA",
            "Regenerate session IDs after login (prevent session fixation)",
            "Set session timeouts: 15min idle, 8hr absolute for web apps",
            "Use secure, httpOnly, SameSite=Strict cookies",
            "Always invalidate sessions server-side on logout",
          ]
        },
      ],
    },
    {
      slug: "misconfigurations",
      title: "Common Misconfigurations",
      description: "The most frequently exploited security misconfigurations and how to remediate them.",
      category: "Knowledge Base",
      estimatedRead: 6,
      lastUpdated: "2026-02-01",
      content: [
        { type: "paragraph", content: "Security misconfiguration is the #1 vulnerability category by prevalence (found in 90%+ of tested applications). Most misconfigurations are quick to fix but have high impact when exploited." },
        { type: "heading2", content: "Top Misconfigurations", id: "top-misconfigurations" },
        {
          type: "table", headers: ["Misconfiguration", "Risk", "Fix"], rows: [
            ["Missing security headers", "XSS, clickjacking, MIME sniffing", "Add HSTS, CSP, X-Frame-Options"],
            ["CORS wildcard (*)", "Cross-origin data theft", "Restrict to specific origins"],
            ["Exposed .env / config files", "Credential exposure", "Add to .gitignore, check web root"],
            ["Directory listing enabled", "File structure disclosure", "Disable in web server config"],
            ["Debug mode in production", "Stack traces, internal info", "FLASK_ENV=production, DEBUG=False"],
            ["Default admin credentials", "Full system compromise", "Force credential change on install"],
            ["Unnecessary open ports", "Attack surface expansion", "Firewall rules, minimize exposure"],
            ["Verbose error messages", "Technology disclosure", "Generic error pages for production"],
          ]
        },
        { type: "heading2", content: "Environment-Specific Hardening", id: "hardening" },
        {
          type: "code", language: "python", content: `# Django production settings checklist
DEBUG = False  # CRITICAL: never True in production
ALLOWED_HOSTS = ['yourdomain.com']  # Not ['*']
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'` },
        { type: "tip", content: "Run Quantara's Misconfiguration Engine monthly to catch configuration drift — changes made by team members that inadvertently reduce security posture." },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// MASTER EXPORT
// ─────────────────────────────────────────────────────────────────────────────

export const docsSections: DocSection[] = [
  gettingStarted,
  installationSetup,
  scannerModules,
  aiCopilot,
  dashboardGuide,
  tutorials,
  knowledgeBase,
];

export const allArticles: DocArticle[] = docsSections.flatMap(s => s.articles);

export function getArticleBySlug(slug: string): DocArticle | undefined {
  return allArticles.find(a => a.slug === slug);
}

export function getSectionByArticleSlug(slug: string): DocSection | undefined {
  return docsSections.find(s => s.articles.some(a => a.slug === slug));
}

export function getAdjacentArticles(slug: string): { prev: DocArticle | null; next: DocArticle | null } {
  const idx = allArticles.findIndex(a => a.slug === slug);
  return {
    prev: idx > 0 ? allArticles[idx - 1] : null,
    next: idx < allArticles.length - 1 ? allArticles[idx + 1] : null,
  };
}

export function searchArticles(query: string): DocArticle[] {
  if (!query.trim()) return [];
  const q = query.toLowerCase();
  return allArticles.filter(article => {
    const text = [
      article.title,
      article.description,
      article.category,
      ...article.content.map(b => {
        if ("content" in b && typeof b.content === "string") return b.content;
        if ("items" in b) return (b.items as string[]).join(" ");
        if ("rows" in b) return (b.rows as string[][]).flat().join(" ");
        if ("title" in b && typeof (b as { title?: string }).title === "string") return (b as { title?: string }).title;
        return "";
      }),
    ].join(" ").toLowerCase();
    return text.includes(q);
  });
}
