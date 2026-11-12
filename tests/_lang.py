"""Pin the output language for tests.

Import this module first in every test file (``import _lang``). It fixes
``KNOWN_SECRET_GUARD_LANG=en`` at import time, so the English assertions hold
under pytest, ``python -m unittest`` and Korean locales alike.
"""

import os

os.environ["KNOWN_SECRET_GUARD_LANG"] = "en"
