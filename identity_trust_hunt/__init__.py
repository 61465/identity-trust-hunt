"""
identity-trust-hunt — Reference implementation of the Provider Trust Boundary (PTB) framework.

Public teaching edition v0.1. Full methodology at
https://github.com/61465/identity-trust-hunt/blob/main/docs/METHODOLOGY.md
"""

__version__ = "0.1.0"
__author__ = "NEXUS Zone Research"
__email__ = "abdarahman10555@gmail.com"
__license__ = "MIT"

from .providers import PUBLIC_PROVIDERS, Provider, ClaimContract
from .rule_engine import PTBFinding, scan_target
from .code_scanner import ClaimAccess, scan_for_claim_access

__all__ = [
    "__version__",
    "PUBLIC_PROVIDERS",
    "Provider",
    "ClaimContract",
    "PTBFinding",
    "scan_target",
    "ClaimAccess",
    "scan_for_claim_access",
]
