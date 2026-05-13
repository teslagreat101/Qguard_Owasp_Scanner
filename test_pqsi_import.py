import sys
import os
from pathlib import Path

# Mimic backend/main.py sys.path setup
# Assuming current dir is c:\Users\HP\Music\AGI-Full_Stack\Owasp_Scanner_Final\
PARENT_DIR = os.getcwd()
CENTRAL_DIR = os.path.join(PARENT_DIR, "Centralize_Scanners")

if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
if CENTRAL_DIR not in sys.path:
    sys.path.insert(0, CENTRAL_DIR)

print(f"PARENT_DIR: {PARENT_DIR}")
print(f"CENTRAL_DIR: {CENTRAL_DIR}")

try:
    from quantum_protocol.intelligence.quantum_timeline import QuantumTimelineEngine
    from quantum_protocol.core.engine import compute_qqsi_score as _compute_qqsi
    print("PQSI_IMPORT_SUCCESS: True")
except Exception as e:
    print(f"PQSI_IMPORT_SUCCESS: False, Error: {e}")
