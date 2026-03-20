"""
Base validator abstractions for vulnerability confirmation.

Provides the core data structures and abstract interface that all
vulnerability-type-specific validators must implement.
"""

from __future__ import annotations

import enum
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ValidationStatus(str, enum.Enum):
    """Possible outcomes of a validation check."""

    CONFIRMED = "CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


@dataclass
class ValidationResult:
    """Structured result of a vulnerability validation."""

    status: ValidationStatus
    evidence: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.status == ValidationStatus.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "evidence": self.evidence,
            "details": self.details,
        }


class BaseValidator(ABC):
    """Abstract base class for vulnerability validators.

    Each concrete validator implements confirmation logic for a specific
    vulnerability type (e.g. RCE, SSRF, command injection).
    """

    @property
    @abstractmethod
    def vuln_type(self) -> str:
        """Return the canonical vulnerability type string (e.g. 'rce')."""
        ...

    @abstractmethod
    def validate(self, response: dict[str, Any]) -> ValidationResult:
        """Validate whether the response confirms the vulnerability.

        Args:
            response: A dictionary containing at minimum:
                - stdout (str): Standard output from the PoC execution.
                - stderr (str): Standard error from the PoC execution.
                - exit_code (int): Process exit code.
                - duration_seconds (float): Execution wall-clock time.
                Additional keys may be present depending on the vuln type.

        Returns:
            A ValidationResult indicating the confirmation status.
        """
        ...

    def _safe_get(self, response: dict[str, Any], key: str, default: Any = "") -> Any:
        """Safely retrieve a value from the response dict."""
        return response.get(key, default)


class ValidatorRegistry:
    """Registry mapping vulnerability type strings to validator classes.

    Usage::

        registry = ValidatorRegistry()
        registry.register("rce", RCEValidator)
        validator = registry.get("rce")
        result = validator.validate(response_data)
    """

    def __init__(self) -> None:
        self._registry: dict[str, type[BaseValidator]] = {}

    def register(self, vuln_type: str, validator_cls: type[BaseValidator]) -> None:
        """Register a validator class for a given vulnerability type."""
        if vuln_type in self._registry:
            logger.warning(
                "Overwriting existing validator for '%s': %s -> %s",
                vuln_type,
                self._registry[vuln_type].__name__,
                validator_cls.__name__,
            )
        self._registry[vuln_type] = validator_cls

    def get(self, vuln_type: str) -> Optional[BaseValidator]:
        """Instantiate and return a validator for *vuln_type*, or None."""
        cls = self._registry.get(vuln_type)
        if cls is None:
            logger.warning("No validator registered for vuln type '%s'", vuln_type)
            return None
        return cls()

    def list_types(self) -> list[str]:
        """Return all registered vulnerability types."""
        return sorted(self._registry.keys())

    def __contains__(self, vuln_type: str) -> bool:
        return vuln_type in self._registry
