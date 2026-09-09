"""
parsers/base_parser.py
----------------------
Abstract Base Parser definition for format-specific structural extraction.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseParser(ABC):
    """
    Abstract parser interface for extracting structured fields from raw security logs.

    Core Guarantees:
    - Never mutates the input raw_content string.
    - Missing fields must remain None / null (no data fabrication).
    - Unparsable or malformed input must fail safely without raising unhandled exceptions.
    """

    name: str = "BaseParser"
    version: str = "1.0.0"
    supported_formats: list[str] = []

    @abstractmethod
    def parse(self, raw_content: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Parse raw event content into a structured dictionary of extracted fields.

        Returns a dictionary containing:
        - success: bool
        - fields: Dict[str, Any] (extracted raw fields)
        - error: Optional[str]
        - timestamp: Optional[datetime]
        - confidence_deductions: List[str]
        """
        pass
