"""Server CLI implementation for enterprise VPN."""

import os
import sys
import click
import logging
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from typing import Optional, Dict

from ..core import WireGuardAdapter, WireGuardMode, WireGuardError
from ..security import DemoAuthenticator
from ..utils import setup_logging, format_error_message

console = Console()

@click.group()
def server():
    """Enterprise VPN server management."""
    pass

@server.command()
@click.option('--endpoint', default='0.0.0.0', help='Server endpoint (IP or hostname)')
@click.option('--subnet', default='10.0.0.0/24', help='VPN subnet')
@click.option('--port', default=51820, help='WireGuard port')
@click.option('--config-dir', default='/etc/wireguard', help='Configuration directory')
def start(endpoint: str, subnet: str, port: int, config_dir: str):
    """Start the VPN server."""
    try:
        setup_logging()
        logger = logging.getLogger('server_cli')
        
        console.print("\nInitializing VPN Server...")
        
        # Initialize WireGuard adapter in server mode
        adapter = WireGuardAdapter(
            server_endpoint=endpoint,
            subnet=subnet,
            mode=WireGuardMode.SERVER
        )
        
        # Get server info
        server_info = adapter.get_server_info()
        
        # Display server information
        console.print("\n✓ Server initialized successfully", style="green")
        console.print("──────────────────────────────────────────────────")
        console.print(f"Endpoint: {endpoint}")
        console.print(f"Subnet: {subnet}")
        console.print(f"Port: {port}")
        console.print(f"Interface: {server_info.get('interface', 'wg0')}")
        console.print(f"Config Path: {server_info.get('config_path', 'N/A')}")
        console.print(f"Public Key: {server_info.get('public_key', 'N/A')}")
        console.print("──────────────────────────────────────────────────")
        
        console.print("\nServer is running. Press Ctrl+C to stop.")
        
        # TODO: Implement proper server event loop
        # For now, just keep the process running
        try:
            import signal
            signal.pause()
        except KeyboardInterrupt:
            console.print("\nShutting down server...")
        
    except WireGuardError as e:
        console.print(format_error_message(e, "Failed to start VPN server"))
        sys.exit(1)
    except Exception as e:
        console.print(format_error_message(e, "Unexpected error occurred"))
        sys.exit(1)

if __name__ == '__main__':
    server() 