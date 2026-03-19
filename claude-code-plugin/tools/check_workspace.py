#!/usr/bin/env python3
"""
Workspace audit tool — verify pipeline artifact completeness for one or all runs.

Usage:
    # Audit all runs under analyzer/
    python3 tools/check_workspace.py

    # Audit a single workspace
    python3 tools/check_workspace.py analyzer/mlflow/workspace

    # Exit with non-zero code if any issues found (useful for CI)
    python3 tools/check_workspace.py --strict
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
ANALYZER_DIR = REPO_ROOT / "analyzer"

# Expected artifacts per pipeline step
MANDATORY_ARTIFACTS = [
    ("target.json", 1, "Step 1 — target extraction"),
    ("Dockerfile", 2, "Step 2 — environment setup"),
    ("docker-compose.yml", 2, "Step 2 — environment setup"),
    ("ENVIRONMENT_SETUP.md", 2, "Step 2 — environment setup"),
    ("vulnerabilities.json", 4, "Step 4 — vulnerability analysis"),
    ("poc_manifest.json", 5, "Step 5 — PoC generation"),
    ("results.json", 7, "Step 7 — reproduction + validation"),
]

REPORT_ARTIFACTS = [
    ("report/REPORT.md", 9, "Step 9 — report generation"),
    ("report/summary.json", 9, "Step 9 — report generation"),
]

POC_NAMING_PATTERN = re.compile(
    r"^poc_(rce|ssrf|dos|command_injection|arbitrary_file_rw|"
    r"insecure_deserialization|path_traversal|lfi|xss|idor)_(\d{3})\.py$"
)

VALID_STATUS_VALUES = {"CONFIRMED", "NOT_REPRODUCED", "ERROR", "MAX_RETRIES"}
FORBIDDEN_STATUS_VALUES = {"SUCCESS", "[SUCCESS]", "FAILED", "[FAILED]", "confirmed"}


class Issue(NamedTuple):
    severity: str   # ERROR | WARN | INFO
    category: str
    message: str


def audit_workspace(workspace: Path) -> list[Issue]:
    issues: list[Issue] = []
    app = workspace.parent.name

    # ── 1. Pipeline state ──────────────────────────────────────────────────────
    ps_path = workspace / "pipeline_state.json"
    current_step = 9  # assume complete if no state file
    if ps_path.exists():
        try:
            ps = json.loads(ps_path.read_text())
            current_step = ps.get("current_step", 9)
            overall = ps.get("overall_status", "completed")
            if overall in ("running", "pending") and current_step < 9:
                issues.append(Issue(
                    "ERROR", "incomplete_pipeline",
                    f"Pipeline stopped at Step {current_step} (status={overall}). "
                    f"Steps {current_step + 1}–9 were never run."
                ))
        except json.JSONDecodeError as e:
            issues.append(Issue("ERROR", "corrupt_json",
                                f"pipeline_state.json is not valid JSON: {e}"))

    # ── 2. Mandatory artifacts ─────────────────────────────────────────────────
    for artifact, step, description in MANDATORY_ARTIFACTS:
        path = workspace / artifact
        if not path.exists():
            # Only flag if that step should have run
            if step <= current_step:
                issues.append(Issue(
                    "ERROR", "missing_artifact",
                    f"Missing {artifact} — produced by {description}"
                ))
            else:
                issues.append(Issue(
                    "INFO", "not_yet_produced",
                    f"Missing {artifact} — pipeline stopped before {description}"
                ))

    # ── 3. Report artifacts ────────────────────────────────────────────────────
    for artifact, step, description in REPORT_ARTIFACTS:
        path = workspace / artifact
        if not path.exists():
            if step <= current_step:
                issues.append(Issue(
                    "ERROR", "missing_report",
                    f"Missing {artifact} — {description} was marked complete but produced no output"
                ))

    # ── 4. Dockerfile checks ───────────────────────────────────────────────────
    dockerfile = workspace / "Dockerfile"
    if dockerfile.exists():
        content = dockerfile.read_text()
        if "HEALTHCHECK" not in content:
            issues.append(Issue(
                "WARN", "dockerfile_no_healthcheck",
                "Dockerfile is missing HEALTHCHECK — container readiness cannot be auto-verified"
            ))
        if "uv" not in content:
            issues.append(Issue(
                "WARN", "dockerfile_no_uv",
                "Dockerfile does not use uv — all Python deps must be managed via uv (see CLAUDE.md §7)"
            ))
        # Check for absolute host paths that hurt reproducibility
        suspicious = re.findall(r"(?:COPY|ADD|WORKDIR)\s+(/(?:home|Users|root/[^.])[\w/.-]+)", content)
        for p in suspicious:
            issues.append(Issue(
                "WARN", "dockerfile_absolute_path",
                f"Dockerfile contains host-absolute path '{p}' — use relative paths or build ARGs instead"
            ))

    # ── 5. PoC script checks ───────────────────────────────────────────────────
    poc_dir = workspace / "poc_scripts"
    if poc_dir.exists():
        for f in sorted(poc_dir.iterdir()):
            if not f.is_file():
                continue
            name = f.name
            if name.endswith(".py"):
                if name.startswith("poc_"):
                    if not POC_NAMING_PATTERN.match(name):
                        # Check for version-suffix pattern (retry artifact)
                        if re.match(r"^poc_.*_\d{3}_v\d+\.py$", name):
                            issues.append(Issue(
                                "WARN", "poc_version_suffix",
                                f"poc_scripts/{name} has a _vN retry suffix — "
                                f"rename to the canonical poc_<type>_NNN.py or remove if superseded"
                            ))
                        else:
                            issues.append(Issue(
                                "WARN", "poc_bad_name",
                                f"poc_scripts/{name} does not match naming convention "
                                f"poc_<type>_NNN.py (valid types: rce, ssrf, dos, "
                                f"command_injection, arbitrary_file_rw, insecure_deserialization)"
                            ))
                else:
                    issues.append(Issue(
                        "WARN", "poc_dir_non_poc_file",
                        f"poc_scripts/{name} is not a PoC script — "
                        f"helper/utility files belong in workspace/ root, not poc_scripts/"
                    ))

    # ── 6. results.json schema checks ─────────────────────────────────────────
    results_path = workspace / "results.json"
    if results_path.exists():
        try:
            results = json.loads(results_path.read_text())
            # Top-level keys
            for key in ("target", "summary", "results"):
                if key not in results:
                    issues.append(Issue(
                        "ERROR", "results_schema",
                        f"results.json missing required top-level key '{key}'"
                    ))
            # Per-result checks
            for r in results.get("results", []):
                status = r.get("status", "")
                if status in FORBIDDEN_STATUS_VALUES:
                    issues.append(Issue(
                        "ERROR", "results_bad_status",
                        f"results.json vuln {r.get('vuln_id','?')}: status='{status}' is forbidden — "
                        f"use CONFIRMED / NOT_REPRODUCED / ERROR / MAX_RETRIES"
                    ))
                elif status not in VALID_STATUS_VALUES:
                    issues.append(Issue(
                        "WARN", "results_unknown_status",
                        f"results.json vuln {r.get('vuln_id','?')}: unknown status='{status}'"
                    ))
                for key in ("vuln_id", "type", "poc_script", "status", "retries"):
                    if key not in r:
                        issues.append(Issue(
                            "WARN", "results_schema",
                            f"results.json vuln {r.get('vuln_id','?')}: missing key '{key}'"
                        ))
        except json.JSONDecodeError as e:
            issues.append(Issue("ERROR", "corrupt_json",
                                f"results.json is not valid JSON: {e}"))

    # ── 7. Stray workspace artifacts ───────────────────────────────────────────
    # Listener/temp .log and .pid files (not build.log which is expected)
    for f in workspace.iterdir():
        if f.is_file() and f.suffix == ".pid":
            issues.append(Issue(
                "WARN", "stray_artifact",
                f"{f.name} — stale PID file should be removed after validation (see exploiter Phase 8)"
            ))
        elif f.is_file() and f.suffix == ".log" and f.name != "build.log":
            issues.append(Issue(
                "WARN", "stray_artifact",
                f"{f.name} — listener log should be cleaned up after validation (see exploiter Phase 8)"
            ))

    # .idea or other IDE directories
    for d in workspace.iterdir():
        if d.is_dir() and d.name.startswith("."):
            issues.append(Issue(
                "WARN", "stray_artifact",
                f"{d.name}/ — IDE/hidden directory should not be committed to workspace"
            ))

    return issues


def format_issues(app: str, issues: list[Issue]) -> str:
    if not issues:
        return f"  OK  {app}"
    lines = [f"  {app}:"]
    for issue in issues:
        icon = {"ERROR": "[!]", "WARN": "[~]", "INFO": "[-]"}.get(issue.severity, "[?]")
        lines.append(f"    {icon} [{issue.category}] {issue.message}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit vuln-analysis workspace artifact completeness"
    )
    parser.add_argument(
        "workspace", nargs="?", default=None,
        help="Path to a specific workspace directory. Defaults to all under analyzer/"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 if any ERROR-level issues are found"
    )
    parser.add_argument(
        "--errors-only", action="store_true",
        help="Only show ERROR-level issues (suppress WARN and INFO)"
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output results as JSON"
    )
    args = parser.parse_args()

    if args.workspace:
        workspaces = [Path(args.workspace).resolve()]
    else:
        workspaces = sorted(
            p / "workspace"
            for p in ANALYZER_DIR.iterdir()
            if p.is_dir() and (p / "workspace").is_dir()
        )

    all_results: dict[str, list[dict]] = {}
    total_errors = 0
    total_warns = 0

    for ws in workspaces:
        app = ws.parent.name
        issues = audit_workspace(ws)

        if args.errors_only:
            issues = [i for i in issues if i.severity == "ERROR"]

        errors = [i for i in issues if i.severity == "ERROR"]
        warns = [i for i in issues if i.severity == "WARN"]
        total_errors += len(errors)
        total_warns += len(warns)

        all_results[app] = [i._asdict() for i in issues]

        if not args.json_output:
            print(format_issues(app, issues))

    if args.json_output:
        print(json.dumps(all_results, indent=2))
    else:
        print()
        print(f"Summary: {len(workspaces)} workspaces | {total_errors} errors | {total_warns} warnings")

    if args.strict and total_errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
