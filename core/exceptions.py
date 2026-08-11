"""core/exceptions.py - Custom exception hierarchy for the platform."""


class ITRAPBaseException(Exception):
    """Base exception for all platform-specific errors."""


class ConfigurationError(ITRAPBaseException):
    """Raised when configuration is invalid or missing required values."""


class ParsingError(ITRAPBaseException):
    """Raised when an input log source cannot be parsed into the normalized model."""


class DetectionRuleError(ITRAPBaseException):
    """Raised when a detection rule fails to execute correctly."""


class DatabaseError(ITRAPBaseException):
    """Raised for database connection or query failures."""


class ThreatIntelError(ITRAPBaseException):
    """Raised when a threat intelligence provider fails or returns invalid data."""


class ResponseActionError(ITRAPBaseException):
    """Raised when an automated response action fails or is blocked by policy."""


class ReportGenerationError(ITRAPBaseException):
    """Raised when report generation (PDF/HTML/CSV) fails."""


class ValidationError(ITRAPBaseException):
    """Raised when input data fails validation checks."""
