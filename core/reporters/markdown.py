"""
Markdown report generator for vulnerability analysis results.

Produces a comprehensive, human-readable report containing an executive
summary, per-vulnerability details, and environment information.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Optional

from ._risk import compute_risk


class MarkdownReporter:
    """Generates a Markdown vulnerability analysis report.

    Args:
        target: Metadata about the scan target (URL, name, version, etc.).
        vulns: List of vulnerability descriptors from the manifest.
        results: List of execution + validation result dicts.
    """

    def __init__(
        self,
        target: dict[str, Any],
        vulns: list[dict[str, Any]],
        results: list[dict[str, Any]],
    ) -> None:
        self.target = target
        self.vulns = vulns
        self.results = results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render(self) -> str:
        """Render the full Markdown report as a string."""
        sections = [
            self._render_header(),
            self._render_executive_summary(),
            self._render_vulnerability_details(),
            self._render_environment_info(),
            self._render_footer(),
        ]
        return "\n\n".join(sections) + "\n"

    def write(self, output_path: str) -> str:
        """Render and write the report to *output_path*. Returns the path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.render()
        path.write_text(content, encoding="utf-8")
        return str(path)

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_header(self) -> str:
        target_name = self.target.get("name", "Unknown Target")
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        return "\n".join(
            [
                f"# Vulnerability Analysis Report: {target_name}",
                "",
                f"**Generated:** {timestamp}  ",
                f"**Target URL:** `{self.target.get('url', 'N/A')}`  ",
                f"**Target Version:** {self.target.get('version', 'N/A')}  ",
            ]
        )

    def _render_executive_summary(self) -> str:
        total = len(self.results)
        confirmed = sum(
            1 for r in self.results if r.get("validation", {}).get("status") == "CONFIRMED"
        )
        partial = sum(
            1 for r in self.results if r.get("validation", {}).get("status") == "PARTIAL"
        )
        not_repro = sum(
            1 for r in self.results if r.get("validation", {}).get("status") == "NOT_REPRODUCED"
        )
        errors = sum(
            1 for r in self.results if r.get("validation", {}).get("status") == "ERROR"
        )

        severity = compute_risk(confirmed, partial, total)

        lines = [
            "## Executive Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total PoCs Executed | {total} |",
            f"| Confirmed | {confirmed} |",
            f"| Partial | {partial} |",
            f"| Not Reproduced | {not_repro} |",
            f"| Errors | {errors} |",
            "",
            f"**Overall Risk Level:** {severity}",
        ]
        return "\n".join(lines)

    def _render_vulnerability_details(self) -> str:
        if not self.results:
            return "## Vulnerability Details\n\nNo results to display."

        sections = ["## Vulnerability Details"]
        for idx, result in enumerate(self.results, start=1):
            sections.append(self._render_single_vuln(idx, result))
        return "\n\n".join(sections)

    def _render_single_vuln(self, index: int, result: dict[str, Any]) -> str:
        name = result.get("script_name", "Unknown")
        vuln_type = result.get("vuln_type", "unknown")
        validation = result.get("validation", {})
        status = validation.get("status", "N/A")
        evidence = validation.get("evidence", "")
        details = validation.get("details", {})

        exit_code = result.get("exit_code", "N/A")
        duration = result.get("duration_seconds", 0)
        timed_out = result.get("timed_out", False)
        error = result.get("error", "")

        status_icon = {
            "CONFIRMED": "[CONFIRMED]",
            "PARTIAL": "[PARTIAL]",
            "NOT_REPRODUCED": "[NOT REPRODUCED]",
            "ERROR": "[ERROR]",
        }.get(status, "[?]")

        lines = [
            f"### {index}. {name} ({vuln_type}) {status_icon}",
            "",
            f"- **Status:** {status}",
            f"- **Exit Code:** {exit_code}",
            f"- **Duration:** {duration:.2f}s",
        ]

        if timed_out:
            lines.append("- **Note:** Execution timed out")

        if error:
            lines.append(f"- **Error:** {error}")

        if evidence:
            lines.extend(
                [
                    "",
                    "**Evidence:**",
                    "```",
                    evidence[:500],
                    "```",
                ]
            )

        if details:
            lines.extend(
                [
                    "",
                    "**Validation Details:**",
                ]
            )
            for k, v in details.items():
                lines.append(f"- {k}: {v}")

        # Include truncated stdout/stderr if available
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        if stdout.strip():
            lines.extend(
                [
                    "",
                    "<details>",
                    "<summary>stdout (click to expand)</summary>",
                    "",
                    "```",
                    stdout[:2000],
                    "```",
                    "",
                    "</details>",
                ]
            )

        if stderr.strip():
            lines.extend(
                [
                    "",
                    "<details>",
                    "<summary>stderr (click to expand)</summary>",
                    "",
                    "```",
                    stderr[:2000],
                    "```",
                    "",
                    "</details>",
                ]
            )

        return "\n".join(lines)

    def _render_environment_info(self) -> str:
        env = self.target.get("environment", {})
        lines = [
            "## Environment",
            "",
            f"| Property | Value |",
            f"|----------|-------|",
            f"| Target Name | {self.target.get('name', 'N/A')} |",
            f"| Target URL | {self.target.get('url', 'N/A')} |",
            f"| Target Version | {self.target.get('version', 'N/A')} |",
        ]

        for key, value in env.items():
            lines.append(f"| {key} | {value} |")

        return "\n".join(lines)

    def _render_footer(self) -> str:
        return "\n".join(
            [
                "---",
                "",
                "*This report was generated by the vuln-analysis framework "
                "for authorized security testing purposes only.*",
            ]
        )

# ------------------------------------------------------------------
# Module-level convenience function
# ------------------------------------------------------------------


def generate_report(
    target: dict[str, Any],
    vulns: list[dict[str, Any]],
    results: list[dict[str, Any]],
    output_dir: str,
    filename: Optional[str] = None,
) -> str:
    """Generate a Markdown report and write it to *output_dir*.

    Args:
        target: Target metadata dict.
        vulns: Vulnerability descriptors.
        results: Execution + validation results.
        output_dir: Directory where the report file is written.
        filename: Optional filename (default: report_<timestamp>.md).

    Returns:
        The absolute path of the written report.
    """
    if filename is None:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{ts}.md"

    output_path = str(Path(output_dir) / filename)
    reporter = MarkdownReporter(target, vulns, results)
    return reporter.write(output_path)
