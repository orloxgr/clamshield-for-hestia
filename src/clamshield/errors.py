class ClamShieldError(Exception):
    """Safe, user-facing operation error."""


class AccessDenied(ClamShieldError):
    pass


class Conflict(ClamShieldError):
    pass


class EngineError(ClamShieldError):
    pass


class EncryptedContent(EngineError):
    """The engine identified content whose plaintext it could not inspect."""


class CoverageUnavailable(EngineError):
    """The loaded website engine did not prove required coverage reporting."""
