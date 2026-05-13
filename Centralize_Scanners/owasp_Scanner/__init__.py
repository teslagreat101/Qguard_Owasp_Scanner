"""
Quantara Security — Enterprise Vulnerability & Secret Scanner v4.0

A next-generation static analysis engine for detecting security vulnerabilities
and sensitive data across polyglot codebases. Aligned to OWASP Top 10:2025,
PCI-DSS 4.0, and FIPS 140-3 standards.

Key capabilities:
  - Multi-language deep analysis (15+ languages)
  - AST-powered semantic scanning (Python, Java, Go, JS/TS, Rust)
  - Entropy-based secret detection with Shannon + Chi-squared analysis
  - X.509 certificate chain parsing and expiry analysis
  - Secret Exposure threat modeling and risk assessment
  - Security health scoring per-repository
  - SBOM-aware dependency vulnerability scanning
  - Compliance mapping: OWASP, PCI-DSS 4.0, FIPS 140-3, GDPR, HIPAA
  - Output: JSON, SARIF 2.1, CSV, HTML dashboard, SPDX, CycloneDX
  - Plugin architecture for custom rules and analyzers
  - Async-first with streaming progress
  - GitHub / GitLab / Bitbucket / local / archive support
  - Incremental scanning with change-set diffing
  - Enterprise: RBAC metadata, audit trails, scan policies
"""

__version__ = "4.0.0"
__author__ = "Quantara Security Team"
__license__ = "Apache-2.0"
