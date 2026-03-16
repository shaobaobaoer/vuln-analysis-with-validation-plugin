"""
Concrete validator implementations for all supported vulnerability types.

Each validator encapsulates the confirmation logic for its vuln class,
inspecting PoC output (stdout, stderr, timing, exit code) for evidence
that the vulnerability was successfully reproduced.
"""

from __future__ import annotations

import re
from typing import Any

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationStatus,
    ValidatorRegistry,
)

# ---------------------------------------------------------------------------
# Global registry instance
# ---------------------------------------------------------------------------
_registry = ValidatorRegistry()


def get_validator(vuln_type: str) -> BaseValidator | None:
    """Return an instantiated validator for the given vulnerability type."""
    return _registry.get(vuln_type)


def get_registry() -> ValidatorRegistry:
    """Return the module-level ValidatorRegistry."""
    return _registry


# ---------------------------------------------------------------------------
# 1. Remote Code Execution (RCE)
# ---------------------------------------------------------------------------
class RCEValidator(BaseValidator):
    """Confirms RCE by looking for a unique marker string in the output.

    PoC scripts should print a deterministic marker (e.g.
    ``VULN_MARKER_<uuid>``) that is only present if arbitrary code
    actually executed on the target.
    """

    MARKER_PATTERN = r"VULN_MARKER_[A-Za-z0-9_-]+"

    @property
    def vuln_type(self) -> str:
        return "rce"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        match = re.search(self.MARKER_PATTERN, combined)
        if match:
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                evidence=match.group(0),
                details={"source": "stdout+stderr"},
            )

        # Also accept generic command output markers (id, whoami, uname)
        cmd_patterns = [
            r"uid=\d+\(.+?\)\s+gid=\d+",   # id command
            r"(root|www-data|nobody)",        # whoami
            r"Linux\s+\S+\s+\d+\.\d+",       # uname -a
        ]
        for pat in cmd_patterns:
            m = re.search(pat, combined)
            if m:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=m.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(
            status=ValidationStatus.NOT_REPRODUCED,
            details={"stdout_len": len(stdout), "stderr_len": len(stderr)},
        )


# ---------------------------------------------------------------------------
# 2. Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
class SSRFValidator(BaseValidator):
    """Confirms SSRF by checking for connection callback evidence.

    Looks for indicators that the server made an outbound request to an
    attacker-controlled endpoint (callback URL, DNS interaction, etc.).
    """

    CALLBACK_PATTERNS = [
        r"callback[_\s-]*received",
        r"dns[_\s-]*interaction",
        r"HTTP/\d\.\d\s+200",               # successful fetch of internal resource
        r"oastify\.com|burpcollaborator",    # common OOB tools
        r"pingback|SSRF_CONFIRMED",
        r"internal[_\s-]*service[_\s-]*response",
    ]

    @property
    def vuln_type(self) -> str:
        return "ssrf"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.CALLBACK_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 3. Insecure Deserialization
# ---------------------------------------------------------------------------
class InsecureDeserializationValidator(BaseValidator):
    """Confirms insecure deserialization by checking for code execution evidence."""

    EVIDENCE_PATTERNS = [
        r"VULN_MARKER_[A-Za-z0-9_-]+",
        r"uid=\d+",
        r"deserialization[_\s-]*success",
        r"object[_\s-]*instantiated",
        r"(java\.lang\.Runtime|os\.system|exec|eval)\s*\(",
        r"gadget[_\s-]*chain[_\s-]*executed",
    ]

    @property
    def vuln_type(self) -> str:
        return "insecure_deserialization"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.EVIDENCE_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 4. Arbitrary File Read/Write
# ---------------------------------------------------------------------------
class ArbitraryFileRWValidator(BaseValidator):
    """Confirms arbitrary file read/write by checking for file operation success."""

    EVIDENCE_PATTERNS = [
        r"file[_\s-]*(written|created|read)[_\s-]*successfully",
        r"WRITE_CONFIRMED|READ_CONFIRMED",
        r"content[_\s-]*matches",
        r"root:.*:0:0:",               # read /etc/passwd
        r"file[_\s-]*operation[_\s-]*success",
    ]

    @property
    def vuln_type(self) -> str:
        return "arbitrary_file_rw"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.EVIDENCE_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 5. Denial of Service (DoS)
# ---------------------------------------------------------------------------
class DoSValidator(BaseValidator):
    """Confirms DoS by checking for response time degradation.

    The PoC should report timing information. A significant increase
    in response time (or a timeout) indicates a successful DoS.
    """

    DEGRADATION_THRESHOLD_SECONDS = 5.0

    @property
    def vuln_type(self) -> str:
        return "dos"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        duration = self._safe_get(response, "duration_seconds", 0.0)
        timed_out = self._safe_get(response, "timed_out", False)
        stdout = self._safe_get(response, "stdout")

        # Explicit timeout is strong evidence
        if timed_out:
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                evidence=f"Request timed out after {duration:.1f}s",
                details={"duration_seconds": duration, "timed_out": True},
            )

        # Check for degradation markers in output
        degradation_patterns = [
            r"response[_\s-]*time[_\s-]*degraded",
            r"DOS_CONFIRMED",
            r"service[_\s-]*unavailable",
            r"connection[_\s-]*refused",
            r"50[0-9]\s+(Internal\s+Server\s+Error|Service\s+Unavailable)",
        ]
        for pat in degradation_patterns:
            match = re.search(pat, stdout, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"duration_seconds": duration},
                )

        # Check if duration exceeded threshold
        if duration >= self.DEGRADATION_THRESHOLD_SECONDS:
            return ValidationResult(
                status=ValidationStatus.PARTIAL,
                evidence=f"Response took {duration:.1f}s (threshold={self.DEGRADATION_THRESHOLD_SECONDS}s)",
                details={"duration_seconds": duration},
            )

        return ValidationResult(
            status=ValidationStatus.NOT_REPRODUCED,
            details={"duration_seconds": duration},
        )


# ---------------------------------------------------------------------------
# 6. Command Injection
# ---------------------------------------------------------------------------
class CommandInjectionValidator(BaseValidator):
    """Confirms OS command injection by looking for a marker in the response.

    Similar to RCE but specifically targets injection into existing
    commands (e.g. ``; id``, ``| whoami``, ``$(cat /etc/passwd)``).
    """

    MARKER_PATTERNS = [
        r"VULN_MARKER_[A-Za-z0-9_-]+",
        r"uid=\d+\(.+?\)\s+gid=\d+",
        r"CMDI_CONFIRMED",
        r"root:.*:0:0:",
    ]

    @property
    def vuln_type(self) -> str:
        return "command_injection"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.MARKER_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# Auto-registration
# ---------------------------------------------------------------------------
_ALL_VALIDATORS: list[type[BaseValidator]] = [
    RCEValidator,
    SSRFValidator,
    InsecureDeserializationValidator,
    ArbitraryFileRWValidator,
    DoSValidator,
    CommandInjectionValidator,
]

for _cls in _ALL_VALIDATORS:
    _registry.register(_cls().vuln_type, _cls)
