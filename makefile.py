#!/usr/bin/env python3
"""
rttp build script — cross-platform replacement for Make targets.
Usage: python makefile.py [target]
"""

import os
import sys
import subprocess
import shutil

try:
    from rich.console import Console
    from rich.rule import Rule
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


def _print(msg="", style=None):
    if HAS_RICH and console is not None:
        console.print(msg, style=style)
    else:
        print(msg)


def _header(msg):
    if HAS_RICH and console is not None:
        console.print(f"\n  [bold cyan]==> {msg}[/bold cyan]")
    else:
        print(f"\n==> {msg}")


def _success(msg):
    _print(f"  [bold green]✔  {msg}[/bold green]" if HAS_RICH else f"OK  {msg}")


def _error(msg):
    _print(f"  [bold red]✖  {msg}[/bold red]" if HAS_RICH else f"ERR {msg}")


def cargo_bin():
    home = os.environ.get("USERPROFILE") or os.environ.get("HOME", "~")
    candidate = os.path.join(home, ".cargo", "bin", "cargo")
    if sys.platform == "win32":
        candidate += ".exe"
    if os.path.isfile(candidate):
        return candidate
    if shutil.which("cargo"):
        return "cargo"
    _error("cargo not found. Install Rust from https://rustup.rs")
    sys.exit(1)


CARGO = cargo_bin()


def run(*args, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(args, env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)


TARGETS = {}

CATEGORIES = [
    ("🔨  Build",          []),
    ("🧪  Test & Quality", []),
    ("📖  Docs",           []),
    ("🔒  Security",       []),
    ("🚀  Run & Watch",    []),
    ("⚙️   Pipeline",      []),
]

_CATEGORY_INDEX = {label: entries for label, entries in CATEGORIES}

_TARGET_CATEGORY = {
    "build":      "🔨  Build",
    "check":      "🔨  Build",
    "clean":      "🔨  Build",
    "fmt":        "🧪  Test & Quality",
    "fmt-check":  "🧪  Test & Quality",
    "lint":       "🧪  Test & Quality",
    "test":       "🧪  Test & Quality",
    "coverage":   "🧪  Test & Quality",
    "doc":        "📖  Docs",
    "doc-build":  "📖  Docs",
    "audit":      "🔒  Security",
    "deny":       "🔒  Security",
    "run":        "🚀  Run & Watch",
    "watch":      "🚀  Run & Watch",
    "watch-test": "🚀  Run & Watch",
    "bacon":      "🚀  Run & Watch",
    "full":       "⚙️   Pipeline",
    "ci":         "⚙️   Pipeline",
    "help":       "⚙️   Pipeline",
}


def target(name, desc):
    def decorator(fn):
        TARGETS[name] = (desc, fn)
        cat = _TARGET_CATEGORY.get(name)
        if cat and cat in _CATEGORY_INDEX:
            _CATEGORY_INDEX[cat].append((name, desc))
        return fn
    return decorator


@target("help", "Show this help message")
def cmd_help():
    if HAS_RICH and console is not None:
        console.print()
        console.print(Rule("[bold cyan]rttp — Rust HTTP Server Framework[/bold cyan]", style="cyan"))
        for cat_label, entries in CATEGORIES:
            if not entries:
                continue
            console.print(f"\n  [bold yellow]{cat_label}[/bold yellow]\n")
            for name, desc in entries:
                console.print(f"    [bold green]{name:<16}[/bold green]  [dim]{desc}[/dim]")
        console.print()
        console.print(Rule(style="cyan"))
        console.print(
            "\n  Run a target:  [bold green]make <target>[/bold green]"
            "  or  [bold green]python makefile.py <target>[/bold green]\n"
        )
    else:
        print()
        print("rttp - Rust HTTP Server Framework")
        print()
        for cat_label, entries in CATEGORIES:
            if not entries:
                continue
            print(cat_label)
            for name, desc in entries:
                print(f"  {name:<16} {desc}")
            print()


@target("build", "Compile the library and all examples")
def cmd_build():
    _header("Building all targets")
    run(CARGO, "build", "--all-targets")
    _success("Build complete.")


@target("check", "Fast compile check without producing binaries")
def cmd_check():
    _header("Checking")
    run(CARGO, "check", "--all-targets", "--all-features")
    _success("Check passed.")


@target("clean", "Remove all build artifacts")
def cmd_clean():
    _header("Cleaning")
    run(CARGO, "clean")
    _success("Clean complete.")


@target("fmt", "Auto-format all source files with rustfmt")
def cmd_fmt():
    _header("Formatting")
    run(CARGO, "fmt", "--all")
    _success("Format complete.")


@target("fmt-check", "Check formatting without modifying files (used in CI)")
def cmd_fmt_check():
    _header("Checking formatting")
    run(CARGO, "fmt", "--all", "--", "--check")
    _success("Format check passed.")


@target("lint", "Run Clippy — warnings are treated as errors")
def cmd_lint():
    _header("Running Clippy")
    run(CARGO, "clippy", "--all-targets", "--all-features", "--", "-D", "warnings")
    _success("Lint passed.")


@target("test", "Run all unit and integration tests (requires cargo-nextest)")
def cmd_test():
    _header("Running tests")
    run(CARGO, "nextest", "run", "--all-targets", "--all-features")
    _success("Tests passed.")


@target("coverage", "Generate HTML coverage report and open it (requires cargo-llvm-cov)")
def cmd_coverage():
    _header("Generating coverage report")
    run(CARGO, "llvm-cov", "--all-features", "--open")


@target("doc", "Generate documentation and open it in the browser")
def cmd_doc():
    _header("Generating docs")
    run(CARGO, "doc", "--no-deps", "--open")


@target("doc-build", "Generate documentation without opening the browser")
def cmd_doc_build():
    _header("Building docs")
    run(CARGO, "doc", "--no-deps")
    _success("Docs built.")


@target("audit", "Scan dependencies for known security vulnerabilities")
def cmd_audit():
    _header("Running audit")
    run(CARGO, "audit")
    _success("Audit passed.")


@target("deny", "Check licenses, bans, and advisories (requires cargo-deny)")
def cmd_deny():
    _header("Running cargo deny")
    run(CARGO, "deny", "check")
    _success("Deny check passed.")


@target("run", "Run the hello_world example (INFO log level)")
def cmd_run():
    _header("Running hello_world example")
    run(CARGO, "run", "--example", "hello_world", env_extra={"RUST_LOG": "info"})


@target("watch", "Watch for changes and re-run hello_world (requires cargo-watch)")
def cmd_watch():
    _header("Watching (hello_world)")
    run(CARGO, "watch", "-x", "run --example hello_world", env_extra={"RUST_LOG": "info"})


@target("watch-test", "Watch for changes and re-run tests (requires cargo-watch + cargo-nextest)")
def cmd_watch_test():
    _header("Watching (tests)")
    run(CARGO, "watch", "-x", "nextest run --all-targets")


@target("bacon", "Start background code checker (requires bacon)")
def cmd_bacon():
    _header("Starting bacon")
    bacon = shutil.which("bacon")
    if not bacon:
        _error("bacon not found. Install with: cargo install bacon")
        sys.exit(1)
    run(bacon)


@target("full", "Run check, lint, and test")
def cmd_full():
    cmd_check()
    cmd_lint()
    cmd_test()
    _success("All checks passed.")


@target("ci", "Simulate the full CI pipeline (fmt-check → check → lint → test → audit → deny)")
def cmd_ci():
    cmd_fmt_check()
    cmd_check()
    cmd_lint()
    cmd_test()
    cmd_audit()
    cmd_deny()
    _success("CI pipeline passed.")


if __name__ == "__main__":
    if not HAS_RICH:
        print("Tip: install 'rich' for colored output  ->  pip install rich")

    target_name = sys.argv[1] if len(sys.argv) > 1 else "help"

    if target_name not in TARGETS:
        _error(f"Unknown target: '{target_name}'")
        _print("Run  python makefile.py help  to see available targets.")
        sys.exit(1)

    _, fn = TARGETS[target_name]
    fn()
