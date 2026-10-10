"""Pytest configuration: ensure backend imports resolve for all test modules.

The project uses sys.path manipulation (see app_launcher.py) to make the
``backend/`` directory importable.  This conftest replicates that setup so
that both ``backend.*`` imports (used by tests) and direct ``database.*``,
``scanners.*``, ``services.*`` imports (used by the application code) work
under pytest without an explicit PYTHONPATH.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.join(_ROOT, "backend")

for _path in (_ROOT, _BACKEND):
    if _path not in sys.path:
        sys.path.insert(0, _path)
