"""
JSON summary generator for vulnerability analysis results.

Produces a machine-readable summary suitable for CI/CD integration,
dashboards, and downstream tooling.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from ._risk import compute_risk


def generate_summary(
    target: dict[str, Any],
    vulns: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate a summary dict from target metadata, vulns, and results.

    The returned dict has the following top-level keys:
        - metadata: target info and generation timestamp
        - statistics: aggregate counts by validation status
        - overall_risk: computed risk level string
        - vulnerabilities: per-vuln entries with execution and validation data

    Args:
        target: Target metadata (name, url, version, environment, ...).
        vulns: Vulnerability descriptors from the manifest.
        results: Execution + validation result dicts.

    Returns:
        A JSON-serialisable summary dict.
    """
    confirmed = 0
    partial = 0
    not_reproduced = 0
    errors = 0

    vuln_entries: list[dict[str, Any]] = []

    for result in results:
        validation = result.get("validation", {})
        status = validation.get("status", "ERROR")

        if status == "CONFIRMED":
            confirmed += 1
        elif status == "PARTIAL":
            partial += 1
        elif status == "NOT_REPRODUCED":
            not_reproduced += 1
        else:
            errors += 1

        vuln_entries.append(
            {
                "script_name": result.get("script_name", "unknown"),
                "vuln_type": result.get("vuln_type", "unknown"),
                "exit_code": result.get("exit_code"),
                "duration_seconds": result.get("duration_seconds", 0),
                "timed_out": result.get("timed_out", False),
                "success": result.get("success", False),
                "error": result.get("error"),
                "validation": {
                    "status": status,
                    "evidence": validation.get("evidence", ""),
                    "details": validation.get("details", {}),
                },
            }
        )

    total = len(results)
    overall_risk = compute_risk(confirmed, partial, total)

    summary: dict[str, Any] = {
        "metadata": {
            "target_name": target.get("name", "Unknown"),
            "target_url": target.get("url", ""),
            "target_version": target.get("version", ""),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "environment": target.get("environment", {}),
        },
        "statistics": {
            "total": total,
            "confirmed": confirmed,
            "partial": partial,
            "not_reproduced": not_reproduced,
            "errors": errors,
        },
        "overall_risk": overall_risk,
        "vulnerabilities": vuln_entries,
    }
    return summary


def write_summary(summary: dict[str, Any], output_path: str) -> str:
    """Write a summary dict to a JSON file.

    Args:
        summary: The summary dict (as returned by generate_summary).
        output_path: Destination file path.

    Returns:
        The absolute path of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    return str(path.resolve())


