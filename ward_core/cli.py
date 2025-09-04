import sys
import json
import logging
from pathlib import Path

from . import __version__

def _setup_basic_logging(verbose=False):
    # match current main.py: log to stderr only
    # in non-verbose mode, only show WARNING and above to reduce noise
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

def _default_config_path():
    # when frozen by PyInstaller, sys._MEIPASS points to bundle root
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path.cwd()))
        return base / "config.yaml"
    # source mode: config lives next to this file
    return Path(__file__).parent / "config.yaml"

def main(argv=None):
    argv = list(argv or sys.argv[1:])

    # Fast path for version
    if "--version" in argv:
        print(__version__)
        return 0

    # Check for verbose flag
    verbose = "--verbose" in argv or "-v" in argv
    if "--verbose" in argv:
        argv.remove("--verbose")
    if "-v" in argv:
        argv.remove("-v")

    # Setup logging based on verbose flag
    _setup_basic_logging(verbose)

    # Preserve current --config anywhere behavior
    config_path = None
    if "--config" in argv:
        i = argv.index("--config")
        if i + 1 < len(argv):
            config_path = argv[i + 1]
            del argv[i:i+2]

    if not config_path:
        default_config = _default_config_path()
        if default_config.exists():
            config_path = str(default_config)

    # Lazy import to avoid pulling heavy deps on --version, etc.
    from .application.analyze_device import AnalyzeDeviceUseCase

    use_case = AnalyzeDeviceUseCase(config_path, verbose=verbose)
    result = use_case.execute_from_command_line(argv)

    # Enrich with metadata (camelCase)
    if isinstance(result, dict):
        result.setdefault("metadata", {})
        result["metadata"]["engineVersion"] = __version__
        result["metadata"]["schemaVersion"] = 1

    print(json.dumps(result, indent=2))
    return 0