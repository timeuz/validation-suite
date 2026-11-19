#!/usr/bin/env python3
"""Run all module test suites and print a summary table."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent / "app" / "modules"

_COUNT_PATTERNS = {
    "passed": re.compile(r"(\d+)\s+passed"),
    "failed": re.compile(r"(\d+)\s+failed"),
    "errors": re.compile(r"(\d+)\s+errors?"),
    "skipped": re.compile(r"(\d+)\s+skipped"),
    "warnings": re.compile(r"(\d+)\s+warnings?"),
}


@dataclass
class SuiteResult:
    """Aggregated outcome of a single module pytest run."""

    module: str
    passed: int
    failed: int
    errors: int
    skipped: int
    warnings: int
    duration_s: float
    returncode: int
    output: str

    @property
    def status(self) -> str:
        return "PASS" if self.returncode == 0 else "FAIL"


def _parse_counts(output: str) -> dict[str, int]:
    """Extract pytest summary counts from the final output lines."""
    tail = "\n".join(output.splitlines()[-10:])
    return {
        key: int(match.group(1)) if (match := pattern.search(tail)) else 0
        for key, pattern in _COUNT_PATTERNS.items()
    }


def run_suite(module_name: str, test_file: Path, verbose: bool = False) -> SuiteResult:
    """Execute pytest for a single module test file."""
    cmd = [sys.executable, "-m", "pytest", str(test_file), "-q", "--tb=short"]
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    duration_s = time.perf_counter() - start

    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    if verbose and combined:
        print(f"\n--- {module_name} ---\n{combined}")

    counts = _parse_counts(combined)
    return SuiteResult(
        module=module_name,
        passed=counts["passed"],
        failed=counts["failed"],
        errors=counts["errors"],
        skipped=counts["skipped"],
        warnings=counts["warnings"],
        duration_s=duration_s,
        returncode=proc.returncode,
        output=combined,
    )


def print_table(results: list[SuiteResult]) -> None:
    """Print an ASCII summary table of all test suite results."""
    headers = ("Módulo", "Status", "Passed", "Failed", "Errors", "Skipped", "Warnings", "Tempo (s)")
    rows = [
        (
            r.module,
            r.status,
            str(r.passed),
            str(r.failed),
            str(r.errors),
            str(r.skipped),
            str(r.warnings),
            f"{r.duration_s:.2f}",
        )
        for r in results
    ]
    totals = (
        "TOTAL",
        "PASS" if all(r.returncode == 0 for r in results) else "FAIL",
        str(sum(r.passed for r in results)),
        str(sum(r.failed for r in results)),
        str(sum(r.errors for r in results)),
        str(sum(r.skipped for r in results)),
        str(sum(r.warnings for r in results)),
        f"{sum(r.duration_s for r in results):.2f}",
    )

    widths = [
        max(len(h), *(len(row[i]) for row in (*rows, totals)))
        for i, h in enumerate(headers)
    ]

    def fmt_row(cols: tuple[str, ...]) -> str:
        cells = [
            cols[0].ljust(widths[0]),
            cols[1].ljust(widths[1]),
            *(cols[i].rjust(widths[i]) for i in range(2, len(cols))),
        ]
        return "| " + " | ".join(cells) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print()
    print(sep)
    print(fmt_row(headers))
    print(sep)
    for row in rows:
        print(fmt_row(row))
    print(sep)
    print(fmt_row(totals))
    print(sep)


_SECTION_RE = re.compile(
    r"^=+\s+(FAILURES|ERRORS|warnings summary|short test summary info)\s+=+$"
)
_SUMMARY_TAIL_RE = re.compile(r"^=+\s+.*\s+in\s+[\d.]+s\s+=+$")


def _extract_details(output: str) -> str:
    """Extract FAILURES, ERRORS, warnings summary, and short summary blocks."""
    lines = output.splitlines()
    blocks: list[str] = []
    in_section = False

    for line in lines:
        if _SECTION_RE.match(line):
            in_section = True
            blocks.append(line)
        elif _SUMMARY_TAIL_RE.match(line):
            in_section = False
        elif in_section:
            blocks.append(line)

    return "\n".join(blocks).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Executa os testes dos módulos e exibe um resumo.")
    parser.add_argument(
        "modules",
        nargs="*",
        help="Nomes opcionais dos módulos para rodar (ex: doc_extract mail_verify).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra a saída completa do pytest.")
    parser.add_argument(
        "-d",
        "--details",
        action="store_true",
        help="Detalha falhas, erros e warnings encontrados em cada módulo.",
    )
    args = parser.parse_args()

    test_files = sorted(MODULES_DIR.glob("*/tests.py"))
    if args.modules:
        wanted = set(args.modules)
        test_files = [p for p in test_files if p.parent.name in wanted]
        if not test_files:
            print(f"Nenhum módulo encontrado para: {', '.join(args.modules)}", file=sys.stderr)
            return 2

    results: list[SuiteResult] = []
    for test_file in test_files:
        module_name = test_file.parent.name
        print(f"Executando {module_name}...", flush=True)
        results.append(run_suite(module_name, test_file, verbose=args.verbose))

    print_table(results)

    if args.details and not args.verbose:
        for r in results:
            if r.failed or r.errors or r.warnings or r.returncode != 0:
                details = _extract_details(r.output) or r.output
                print(f"\n=== Detalhes: {r.module} ===\n{details}")

    failed_suites = [r for r in results if r.returncode != 0]
    if failed_suites and not args.verbose and not args.details:
        for r in failed_suites:
            print(f"\n=== Detalhes da falha: {r.module} ===\n{r.output}")

    return 0 if not failed_suites else 1


if __name__ == "__main__":
    raise SystemExit(main())
