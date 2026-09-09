"""
parsers package
---------------
Format-specific structural log parsers for SENTINEL-TRACE.

Sprint 2: BaseParser, SyslogParser, JSONParser, CSVParser.
"""

from app.parsers.base_parser import BaseParser
from app.parsers.csv_parser import CSVParser
from app.parsers.json_parser import JSONParser
from app.parsers.syslog_parser import SyslogParser

PARSER_REGISTRY = {
    "syslog": SyslogParser(),
    "json": JSONParser(),
    "csv": CSVParser(),
    "text": SyslogParser(),  # Default fallback for unstructured/syslog text
}

__all__ = ["BaseParser", "SyslogParser", "JSONParser", "CSVParser", "PARSER_REGISTRY"]
