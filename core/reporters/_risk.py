"""Shared risk-level computation for vulnerability reporters."""

from __future__ import annotations


def compute_risk(confirmed: int, partial: int, total: int) -> str:
    """Compute an overall risk level string from validation counts.

    Args:
        confirmed: Number of fully confirmed vulnerabilities.
        partial:   Number of partially confirmed vulnerabilities.
        total:     Total number of PoCs executed.

    Returns:
        One of: ``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``, ``"UNKNOWN"``.
    """
    if total == 0:
        return "UNKNOWN"
    ratio = (confirmed + partial * 0.5) / total
    if ratio >= 0.5:
        return "CRITICAL"
    if ratio >= 0.25:
        return "HIGH"
    if confirmed > 0 or partial > 0:
        return "MEDIUM"
    return "LOW"
