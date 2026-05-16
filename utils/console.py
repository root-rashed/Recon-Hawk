"""
utils/console.py - Colored terminal output utility for ReconHawk.
"""

import sys


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"


COLOR_MAP = {
    "red":     Colors.RED,
    "green":   Colors.GREEN,
    "yellow":  Colors.YELLOW,
    "blue":    Colors.BLUE,
    "magenta": Colors.MAGENTA,
    "cyan":    Colors.CYAN,
    "white":   Colors.WHITE,
    "gray":    Colors.GRAY,
}


class Console:
    _no_color = False
    _quiet    = False

    @classmethod
    def configure(cls, no_color: bool = False, quiet: bool = False):
        cls._no_color = no_color
        cls._quiet    = quiet

    @classmethod
    def _color(cls, text: str, color: str) -> str:
        if cls._no_color or not sys.stdout.isatty():
            return text
        return f"{COLOR_MAP.get(color, '')}{text}{Colors.RESET}"

    @classmethod
    def _bold(cls, text: str) -> str:
        if cls._no_color or not sys.stdout.isatty():
            return text
        return f"{Colors.BOLD}{text}{Colors.RESET}"

    # ── Public helpers ────────────────────────────────────────────────────────

    @classmethod
    def print_raw(cls, text: str, color: str = "white"):
        if cls._quiet:
            return
        print(cls._color(text, color))

    @classmethod
    def info(cls, msg: str):
        prefix = cls._color("[*]", "blue")
        print(f"{prefix} {msg}")

    @classmethod
    def success(cls, msg: str):
        prefix = cls._color("[+]", "green")
        print(f"{prefix} {msg}")

    @classmethod
    def warning(cls, msg: str):
        prefix = cls._color("[!]", "yellow")
        print(f"{prefix} {msg}")

    @classmethod
    def error(cls, msg: str):
        prefix = cls._color("[-]", "red")
        print(f"{prefix} {msg}", file=sys.stderr)

    @classmethod
    def finding(cls, severity: str, msg: str):
        """Print a vulnerability finding with severity color."""
        sev_colors = {
            "critical": "red",
            "high":     "red",
            "medium":   "yellow",
            "low":      "cyan",
            "info":     "gray",
        }
        color  = sev_colors.get(severity.lower(), "white")
        prefix = cls._color(f"[{severity.upper()[:4]}]", color)
        print(f"  {prefix} {msg}")

    @classmethod
    def section(cls, title: str):
        if cls._quiet:
            return
        bar = cls._color("─" * 60, "gray")
        print(f"\n{bar}")
        print(cls._bold(cls._color(f"  ▶ {title}", "cyan")))
        print(bar)

    @classmethod
    def item(cls, key: str, value: str, indent: int = 2):
        pad = " " * indent
        k   = cls._color(key, "gray")
        print(f"{pad}{k}: {value}")

    @classmethod
    def list_items(cls, items, label: str = "", limit: int = 20):
        if label:
            cls.info(label)
        shown = items[:limit]
        for item in shown:
            print(f"    • {item}")
        if len(items) > limit:
            remaining = len(items) - limit
            cls.warning(f"    ... and {remaining} more (see report)")
