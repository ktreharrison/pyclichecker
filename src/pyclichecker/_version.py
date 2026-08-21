"""Package version lookup."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pyclichecker")
except PackageNotFoundError:
    __version__ = "0+unknown"

VERSION = __version__
