"""
vsac — the Gossamer Suite's dependency risk and threat-correlation tool.

Deliberately does NOT eagerly import `refresh` here: refresh.py is the
only module allowed to `import requests`, and importing vsac itself
(e.g. `import vsac`) should never pull that in. `from vsac import
refresh` still works fine as an explicit, opt-in import -- it's just
not pre-loaded as a package attribute, so it's correctly left out of
__all__ below rather than listed-but-absent.
"""

from . import cache
from . import scan
from . import slopsquat
from . import parsers
from . import schema
from . import cli

__all__ = ["cache", "scan", "slopsquat", "parsers", "schema", "cli"]