class WireGuardError(Exception):
    """Base exception class for WireGuard-related errors."""
    pass

class WireGuardConfigError(WireGuardError):
    """Exception raised for WireGuard configuration errors."""
    pass

class WireGuardConnectionError(WireGuardError):
    """Exception raised for WireGuard connection errors."""
    pass

class WireGuardInterfaceError(WireGuardError):
    """Exception raised for WireGuard interface management errors."""
    pass 