import sys
import os
from pathlib import Path

# Setup paths like orchestrator.py
_ROOT = os.getcwd()
_CENTRAL_DIR = os.path.join(_ROOT, "Centralize_Scanners")
if _CENTRAL_DIR not in sys.path:
    sys.path.insert(0, _CENTRAL_DIR)

print(f"sys.path: {sys.path[:2]}")

try:
    print("Attempting to import CodeSecurityScanner...")
    from code_security_scanner.scanner import CodeSecurityScanner
    print("Import success!")
except Exception:
    import traceback
    traceback.print_exc()
