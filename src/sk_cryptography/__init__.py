"""
Top-level API for sk_cryptography.

- Re-exports all public functions from submodules so you can:
    from crypto_lab import encrypt_caesar_gram, pubkey, rsa_encrypt
- Still lets you access submodules:
    from crypto_lab import rsa
    rsa.rsa_encrypt(...)
"""

__all__ = []

# Import submodules so they're accessible as crypto_lab.rsa, etc.
from . import helper_functions as _helper_functions
from . import caesar_shift as _caesar_shift
from . import diffie_hellman as _diffie_hellman
from . import elliptic_curves as _elliptic_curves
from . import rsa as _rsa

# Make submodules directly importable (optional but handy)
helper_functions = _helper_functions
caesar_shift = _caesar_shift
diffie_hellman = _diffie_hellman
elliptic_curves = _elliptic_curves
rsa = _rsa

__all__ += [
    "helper_functions",
    "caesar_shift",
    "diffie_hellman",
    "elliptic_curves",
    "rsa",
]

def _reexport_functions(mod):
    """
    Re-export all public callables from a module at package top-level.
    Skips names starting with '_' and avoids clobbering existing names.
    """
    for name, obj in vars(mod).items():
        if name.startswith("_"):
            continue
        if callable(obj) and name not in globals():
            globals()[name] = obj
            __all__.append(name)

# Re-export functions from each submodule
for _m in (_helper_functions, _caesar_shift, _diffie_hellman, _elliptic_curves, _rsa):
    _reexport_functions(_m)

# Optional: a version string you can bump manually or automate later
__version__ = "0.1.0"
