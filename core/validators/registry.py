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
# 7. SQL Injection
# ---------------------------------------------------------------------------
class SQLInjectionValidator(BaseValidator):
    """Confirms SQL injection via error-based, time-based, or union-based evidence.

    Evidence is gathered entirely from HTTP response analysis — no direct DB
    connections are permitted (that would bypass the target app's auth layer).
    """

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"syntax error at or near",
        r"ORA-\d{4,5}:",                        # Oracle
        r"unclosed quotation mark",              # MSSQL
        r"microsoft.*odbc.*sql server.*driver",  # MSSQL via ODBC
        r"pg_query\(\):",                        # PostgreSQL PHP
        r"invalid input syntax for type",        # PostgreSQL
        r"sqlite.*error",                        # SQLite
        r"SQLSTATE\[\d+\]",                      # Generic PDO
        r"near\s+[\"']\S+[\"']:\s+syntax error", # SQLite near-syntax
        r"quoted string not properly terminated", # Oracle
        r"SQLI_CONFIRMED",                        # Explicit marker in union-based PoC
    ]

    @property
    def vuln_type(self) -> str:
        return "sql_injection"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        # Error-based or union-based confirmation
        for pat in self.SQL_ERROR_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"technique": "error-based or union-based", "pattern_matched": pat},
                )

        # Time-based blind: PoC reports timing ratio
        time_match = re.search(
            r"time[_\s-]*based.*?(\d+\.?\d*)\s*(?:x|times|×)\s*baseline",
            combined, re.IGNORECASE
        )
        if time_match:
            ratio_str = time_match.group(1)
            try:
                ratio = float(ratio_str)
                if ratio >= 4.0:
                    return ValidationResult(
                        status=ValidationStatus.CONFIRMED,
                        evidence=f"Time-based blind SQLi: {ratio:.1f}× baseline",
                        details={"technique": "time-based", "ratio": ratio},
                    )
            except ValueError:
                pass

        # Boolean-based: PoC reports byte difference
        bool_match = re.search(
            r"boolean[_\s-]*based.*?diff\s*=\s*(-?\d+)",
            combined, re.IGNORECASE
        )
        if bool_match:
            diff = abs(int(bool_match.group(1)))
            if diff >= 50:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=f"Boolean-based SQLi: response diff = {diff} bytes",
                    details={"technique": "boolean-based", "diff_bytes": diff},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 8. Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------
class XSSValidator(BaseValidator):
    """Confirms XSS by finding an unescaped unique marker in the HTML response.

    PoC scripts should inject a unique token (e.g. xss_<hex>) and check that
    it appears in the response body without HTML entity escaping.
    """

    XSS_MARKER_PATTERN = r"xss_[a-f0-9]{8,}"
    HTML_ENTITIES = re.compile(r"&(?:lt|gt|amp|quot|#39|apos);")

    @property
    def vuln_type(self) -> str:
        return "xss"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        # Look for explicit XSS confirmation output from PoC
        if re.search(r"XSS_CONFIRMED|xss[_\s-]*confirmed", combined, re.IGNORECASE):
            marker_match = re.search(self.XSS_MARKER_PATTERN, combined, re.IGNORECASE)
            evidence = marker_match.group(0) if marker_match else "XSS_CONFIRMED marker"
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                evidence=f"XSS confirmed: {evidence} found unescaped in response",
                details={"source": "PoC output"},
            )

        # Look for the marker pattern itself in output
        marker_match = re.search(self.XSS_MARKER_PATTERN, combined, re.IGNORECASE)
        if marker_match:
            # Verify the surrounding context is not HTML-escaped
            marker_pos = combined.find(marker_match.group(0))
            context_window = combined[max(0, marker_pos - 50): marker_pos + 80]
            if not self.HTML_ENTITIES.search(context_window):
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=f"Marker {marker_match.group(0)} found unescaped in HTML response",
                    details={"context": context_window[:100]},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 9. IDOR (Insecure Direct Object Reference)
# ---------------------------------------------------------------------------
class IDORValidator(BaseValidator):
    """Confirms IDOR by detecting successful cross-user resource access.

    PoC scripts register two users and attempt to access user2's resource
    using user1's credentials. Success is indicated by HTTP 200 with
    user2's data in the response.
    """

    IDOR_PATTERNS = [
        r"IDOR_CONFIRMED",
        r"idor[_\s-]*confirmed",
        r"cross[_\s-]*user[_\s-]*access[_\s-]*(?:successful|confirmed)",
        r"horizontal[_\s-]*privilege[_\s-]*escalation[_\s-]*(?:confirmed|successful)",
        r"accessed\s+(?:resource|data)\s+of\s+(?:another|different)\s+user",
    ]

    @property
    def vuln_type(self) -> str:
        return "idor"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.IDOR_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        # Check for PoC reporting HTTP 200 with another user's data
        http_200_match = re.search(
            r"http[_\s-]*(?:code|status)[_\s-]*(?:=|:)\s*200.*?(?:user2|idor_poc_b|target_user)",
            combined, re.IGNORECASE | re.DOTALL
        )
        if http_200_match:
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                evidence="HTTP 200 returned with target user's data",
                details={"source": "PoC response analysis"},
            )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 10. JNDI Injection (Java-specific)
# ---------------------------------------------------------------------------
class JNDIInjectionValidator(BaseValidator):
    """Confirms JNDI injection (e.g. Log4Shell) via callback or RCE evidence.

    PoC scripts inject ${jndi:ldap://...} payloads. Confirmation requires
    either a TCP callback on the listener port or a marker file written via
    remote class loading.
    """

    JNDI_PATTERNS = [
        r"JNDI_CONFIRMED",
        r"jndi[_\s-]*injection[_\s-]*(?:confirmed|successful)",
        r"jndi[_\s-]*lookup[_\s-]*(?:received|triggered|initiated)",
        r"callback[_\s-]*received.*?(?:ldap|rmi|dns)",
        r"remote[_\s-]*class[_\s-]*loaded",
        r"log4shell[_\s-]*(?:confirmed|triggered)",
    ]

    @property
    def vuln_type(self) -> str:
        return "jndi_injection"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.JNDI_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        # Partial: Java CommunicationException referencing attacker host
        partial_patterns = [
            r"CommunicationException.*127\.0\.0\.1",
            r"NamingException.*ldap://",
            r"Connection refused.*59877",
        ]
        for pat in partial_patterns:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.PARTIAL,
                    evidence=f"JNDI lookup attempted but blocked: {match.group(0)[:100]}",
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 11. Prototype Pollution (JavaScript/TypeScript-specific)
# ---------------------------------------------------------------------------
class PrototypePollutionValidator(BaseValidator):
    """Confirms prototype pollution via privilege escalation or RCE via gadget.

    PoC scripts inject __proto__ payloads. Confirmation via:
    - Marker file creation (RCE via template engine gadget chain)
    - Admin property reflected in response (privilege escalation)
    """

    PP_PATTERNS = [
        r"PP_CONFIRMED|PROTOTYPE_POLLUTION_CONFIRMED",
        r"prototype[_\s-]*pollution[_\s-]*(?:confirmed|successful)",
        r"privilege[_\s-]*escalation[_\s-]*confirmed",
        r"rce[_\s-]*via[_\s-]*gadget[_\s-]*(?:confirmed|successful)",
        r"pp[_\s-]*rce[_\s-]*[a-f0-9]{8,}",          # marker file pattern
        r"\"admin\"\s*:\s*true",                        # admin property reflected
        r"\"isAdmin\"\s*:\s*true",
        r"\"role\"\s*:\s*\"admin\"",
    ]

    @property
    def vuln_type(self) -> str:
        return "prototype_pollution"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        for pat in self.PP_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# 12. Pickle Deserialization (Python-specific)
# ---------------------------------------------------------------------------
class PickleDeserializationValidator(BaseValidator):
    """Confirms Python pickle deserialization RCE via marker file or callback.

    PoC scripts send a malicious pickle payload (using __reduce__ to call
    os.system('/tmp/invoke')) to a network-accessible endpoint. Confirmation
    requires a marker file written by the payload OR a TCP callback.

    Python-only: skip if target language is not Python.
    """

    PICKLE_PATTERNS = [
        r"PICKLE_CONFIRMED",
        r"pickle[_\s-]*deserialization[_\s-]*(?:confirmed|successful)",
        r"pickle[_\s-]*rce[_\s-]*[a-f0-9]{8,}",   # /tmp/pickle_rce_<id> pattern
        r"__reduce__.*(?:executed|triggered)",
        r"malicious[_\s-]*pickle[_\s-]*(?:loaded|executed)",
    ]

    PARTIAL_PATTERNS = [
        r"_reconstruct|__reduce__|copyreg\._reconstructor",  # pickle internals in traceback
        r"AttributeError.*__reduce__",
        r"pickle\.UnpicklingError",
        r"PickleError|UnpicklingError",
    ]

    @property
    def vuln_type(self) -> str:
        return "pickle_deserialization"

    def validate(self, response: dict[str, Any]) -> ValidationResult:
        stdout = self._safe_get(response, "stdout")
        stderr = self._safe_get(response, "stderr")
        combined = f"{stdout}\n{stderr}"

        # Full confirmation
        for pat in self.PICKLE_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.CONFIRMED,
                    evidence=match.group(0),
                    details={"pattern_matched": pat},
                )

        # Also accept generic RCE evidence (invoke binary executed)
        rce_match = re.search(r"uid=\d+\(.+?\)\s+gid=\d+|VULN_MARKER_[A-Za-z0-9_-]+", combined)
        if rce_match:
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                evidence=f"RCE confirmed via pickle payload: {rce_match.group(0)}",
                details={"source": "command output"},
            )

        # Partial: pickle internals reached (deserialization attempted)
        for pat in self.PARTIAL_PATTERNS:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                return ValidationResult(
                    status=ValidationStatus.PARTIAL,
                    evidence=f"Pickle deserialization attempted (internal traceback): {match.group(0)[:80]}",
                    details={"pattern_matched": pat},
                )

        return ValidationResult(status=ValidationStatus.NOT_REPRODUCED)


# ---------------------------------------------------------------------------
# Auto-registration — all 12 supported vulnerability types
# ---------------------------------------------------------------------------
_ALL_VALIDATORS: list[tuple[str, type[BaseValidator]]] = [
    ("rce", RCEValidator),
    ("ssrf", SSRFValidator),
    ("insecure_deserialization", InsecureDeserializationValidator),
    ("arbitrary_file_rw", ArbitraryFileRWValidator),
    ("dos", DoSValidator),
    ("command_injection", CommandInjectionValidator),
    ("sql_injection", SQLInjectionValidator),
    ("xss", XSSValidator),
    ("idor", IDORValidator),
    ("jndi_injection", JNDIInjectionValidator),           # Java-only
    ("prototype_pollution", PrototypePollutionValidator), # JS/TS-only
    ("pickle_deserialization", PickleDeserializationValidator),  # Python-only
]

for _vuln_type, _cls in _ALL_VALIDATORS:
    _registry.register(_vuln_type, _cls)
