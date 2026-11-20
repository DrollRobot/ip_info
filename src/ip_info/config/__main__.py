"""Module entry point: ``python -m ip_info.config``."""

from __future__ import annotations

import sys

from ip_info.config.cli import main

if __name__ == "__main__":
    sys.exit(main())
