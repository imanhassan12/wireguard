"""Utility functions for enterprise VPN."""

import os
import logging
from rich.panel import Panel
from rich.text import Text
from typing import Optional

def setup_logging(log_level: int = logging.INFO) -> None:
    """Set up logging configuration.
    
    Args:
        log_level: Logging level (default: INFO)
    """
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            # Console handler
            logging.StreamHandler(),
            # File handler
            logging.FileHandler(os.path.join(log_dir, "enterprise_vpn.log"))
        ]
    )
    
    # Set specific module log levels
    logging.getLogger('wireguard').setLevel(log_level)
    logging.getLogger('auth').setLevel(log_level)
    logging.getLogger('server_cli').setLevel(log_level)

def format_error_message(error: Exception, context: Optional[str] = None) -> Panel:
    """Format error message in a rich panel.
    
    Args:
        error: Exception to format
        context: Optional context about where the error occurred
        
    Returns:
        Rich panel containing formatted error message
    """
    error_text = Text()
    
    if context:
        error_text.append(f"{context}\n\n", style="bold red")
    
    error_text.append("Error: ", style="bold red")
    error_text.append(str(error))
    
    if hasattr(error, '__cause__') and error.__cause__:
        error_text.append("\n\nCaused by: ", style="bold yellow")
        error_text.append(str(error.__cause__))
    
    return Panel(
        error_text,
        title="Error Details",
        border_style="red"
    )

__all__ = [
    'setup_logging',
    'format_error_message'
] 