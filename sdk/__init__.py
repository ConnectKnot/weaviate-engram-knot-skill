"""Drop-in Engram-compatible Python SDK backed by Knot REST APIs."""

from .engram_knot_compat import EngramKnotCompatClient, EngramKnotCompatError

__all__ = ["EngramKnotCompatClient", "EngramKnotCompatError"]
