"""Server CLI implementation for enterprise VPN."""

import os
import sys
import click
import logging
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from typing import Optional, Dict

from ..core import WireGuardAdapter, WireGuardMode, WireGuardError
from ..security import DemoAuthenticator
from ..utils import setup_logging, format_error_message

console = Console()

def cleanup_old_config(config_dir: str = '/etc/wireguard'):
    """Clean up old WireGuard configuration files."""
    try:
        # List of files to clean up
        files_to_remove = [
            os.path.join(config_dir, 'wg0.conf'),
            os.path.join(config_dir, 'wg0-peers.conf'),
            os.path.join(config_dir, 'utun5.conf'),
            os.path.join(config_dir, 'utun5-peers.conf'),
            os.path.join(config_dir, 'utun6.conf'),
            os.path.join(config_dir, 'utun6-peers.conf'),
            os.path.join(config_dir, 'pf.rules')
        ]
        
        # Also try to bring down any existing interfaces
        interfaces = ['wg0', 'utun5', 'utun6']
        for interface in interfaces:
            try:
                subprocess.run(['wg-quick', 'down', interface],
                           capture_output=True,
                           check=False)
                console.print(f"Stopped interface: {interface}", style="yellow")
            except Exception:
                pass
        
        for file_path in files_to_remove:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    console.print(f"Removed old configuration: {file_path}", style="yellow")
                except PermissionError:
                    console.print(f"Permission denied: Cannot remove {file_path}. Are you running with sudo?", style="red")
                    raise
                except Exception as e:
                    console.print(f"Failed to remove {file_path}: {str(e)}", style="red")
        
        # Reset packet filter rules
        try:
            subprocess.run(['/sbin/pfctl', '-F', 'all', '-f', '/etc/pf.conf'],
                       capture_output=True,
                       check=False)
            console.print("Reset packet filter rules", style="yellow")
        except Exception:
            pass
            
    except Exception as e:
        raise WireGuardError(f"Failed to clean up old configuration: {str(e)}")

@click.group()
def server():
    """Enterprise VPN server management."""
    pass

@server.command()
def status():
    """Check VPN server status."""
    try:
        setup_logging()
        logger = logging.getLogger('server_cli')
        
        # Check interface status
        result = subprocess.run(['wg', 'show', 'wg0'],
                            capture_output=True,
                            text=True,
                            check=False)
        
        if result.returncode == 0:
            console.print("\n✓ WireGuard server is running", style="green")
            console.print("\nInterface Status:")
            console.print("──────────────────────────────────────────────────")
            console.print(result.stdout)
            console.print("──────────────────────────────────────────────────")
        else:
            console.print("\n✗ WireGuard server is not running", style="red")
            
    except Exception as e:
        console.print(format_error_message(e, "Failed to get server status"))
        sys.exit(1)

@server.command()
def stop():
    """Stop the VPN server."""
    try:
        setup_logging()
        logger = logging.getLogger('server_cli')
        
        console.print("\nStopping VPN Server...")
        
        # Initialize adapter in server mode
        adapter = WireGuardAdapter(
            server_endpoint="0.0.0.0",  # Dummy value for stopping
            subnet="10.0.0.0/24",      # Dummy value for stopping
            mode=WireGuardMode.SERVER
        )
        
        # Stop the interface
        adapter.stop_interface()
        
        console.print("✓ Server stopped successfully", style="green")
        
    except WireGuardError as e:
        console.print(format_error_message(e, "Failed to stop VPN server"))
        sys.exit(1)
    except Exception as e:
        console.print(format_error_message(e, "Unexpected error occurred"))
        sys.exit(1)

@server.command()
@click.option('--endpoint', default='0.0.0.0', help='Server endpoint (IP or hostname)')
@click.option('--subnet', default='10.0.0.0/24', help='VPN subnet')
@click.option('--port', default=51820, help='WireGuard port')
@click.option('--config-dir', default='/etc/wireguard', help='Configuration directory')
@click.option('--force', is_flag=True, help='Force clean start by removing existing configuration')
def start(endpoint: str, subnet: str, port: int, config_dir: str, force: bool):
    """Start the VPN server."""
    try:
        setup_logging()
        logger = logging.getLogger('server_cli')
        
        console.print("\nInitializing VPN Server...")
        
        # Clean up old configuration if force flag is set
        if force:
            console.print("Force flag set. Cleaning up old configuration...", style="yellow")
            cleanup_old_config(config_dir)
        
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
        
        # Keep the process running and handle signals
        try:
            import signal
            def signal_handler(signum, frame):
                console.print("\nShutting down server...")
                adapter.stop_interface()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            signal.pause()
            
        except KeyboardInterrupt:
            console.print("\nShutting down server...")
            adapter.stop_interface()
        
    except WireGuardError as e:
        console.print(format_error_message(e, "Failed to start VPN server"))
        sys.exit(1)
    except Exception as e:
        console.print(format_error_message(e, "Unexpected error occurred"))
        sys.exit(1)

@server.command()
@click.option('--config-dir', default='/etc/wireguard', help='Configuration directory')
def cleanup(config_dir: str):
    """Clean up WireGuard configuration files."""
    try:
        cleanup_old_config(config_dir)
        console.print("✓ Configuration cleanup completed successfully", style="green")
    except WireGuardError as e:
        console.print(format_error_message(e, "Failed to clean up configuration"))
        sys.exit(1)
    except Exception as e:
        console.print(format_error_message(e, "Unexpected error occurred"))
        sys.exit(1)

if __name__ == '__main__':
    server() 