"""Compatibility wrapper for native experiments and old two-hook comparisons.

Production callers use generic_native.generate_native and its mandatory marker-
safe design. The unsafe historical comparison is available only through this
explicit test wrapper and never grants package generation authority.
"""
from generic_native import pointer, branch, call_branch, profile_source, _materialize


def experiment(original, native, plaintext_safe=False):
    return _materialize(original, native, plaintext_safe=plaintext_safe)
