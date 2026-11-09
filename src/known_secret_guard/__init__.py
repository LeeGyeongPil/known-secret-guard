"""known-secret-guard: catch *known* secret values leaving in disguised form.

Public API: :class:`Guard`, :class:`Finding`, :class:`LeakDetected`,
:class:`GuardConfigError`, :data:`VARIANT_CODES`.
"""

from .findings import Finding, GuardConfigError, LeakDetected
from .guard import Guard
from .variants import VARIANT_CODES

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Guard",
    "GuardConfigError",
    "LeakDetected",
    "VARIANT_CODES",
    "__version__",
]
