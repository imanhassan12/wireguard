"""Command-line interface for enterprise VPN."""

import click
import yaml
import os
from pathlib import Path
from typing import Dict, Optional
from ..core.wireguard_adapter import WireGuardAdapter, WireGuardMode
from ..security.auth import OktaAuthProvider, AuthenticationContext
from ..security.beyondcorp import BeyondCorpValidator
from ..network.connection_manager import ConnectionManager, VPNConnectionError
from ..management.threat_monitoring import ThreatMonitor
from ..network.access_control import AccessController

def load_or_create_config(config_dir: Path) -> Dict:
    """Load or create configuration.
    
    Args:
        config_dir: Configuration directory path
        
    Returns:
        Dict containing configuration
    """
    config_dir.mkdir(exist_ok=True)
    
    # Default configuration
    default_config = {
        'auth': {
            'domain': 'your-okta-domain',
            'api_token': 'your-api-token'
        },
        'security': {
            'max_risk_level': 'MEDIUM',
            'device_trust_required': True
        },
        'monitoring': {
            'metrics_interval': 60,
            'threat_check_interval': 30
        }
    }
    
    config_file = config_dir / 'config.yaml'
    if config_file.exists():
        try:
            with open(config_file) as f:
                config = yaml.safe_load(f)
                if not config:
                    config = default_config
        except Exception as e:
            click.echo(f"Error loading config: {str(e)}", err=True)
            config = default_config
    else:
        config = default_config
        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f)
        except Exception as e:
            click.echo(f"Warning: Could not save default config: {str(e)}", err=True)
    
    return config

def save_connection_info(config_dir: Path, server: str, subnet: str):
    """Save connection information.
    
    Args:
        config_dir: Configuration directory path
        server: Server endpoint
        subnet: VPN subnet
    """
    connection_info = {
        'server': {
            'endpoint': server,
            'subnet': subnet
        }
    }
    
    try:
        with open(config_dir / 'connection.yaml', 'w') as f:
            yaml.dump(connection_info, f)
    except Exception as e:
        click.echo(f"Warning: Could not save connection info: {str(e)}", err=True)

def display_connection_error(error: VPNConnectionError):
    """Display detailed connection error information."""
    click.echo("\n❌ Connection Failed")
    click.echo("─" * 50)
    
    # Display error message
    click.echo(f"Error: {str(error)}")
    
    # Display error details based on type
    if error.details.get('error_type') == 'server_connectivity':
        click.echo("\nServer Connection Issue:")
        click.echo(f"• Server: {error.details.get('server')}")
        click.echo(f"• Details: {error.details.get('details')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Check if the server address is correct")
        click.echo("2. Verify the server is running")
        click.echo("3. Check your network connection")
        click.echo("4. Ensure the VPN port (51820) is not blocked")
        
    elif error.details.get('error_type') == 'network_config':
        click.echo("\nNetwork Configuration Issue:")
        click.echo(f"• Details: {error.details.get('details')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Verify the subnet configuration")
        click.echo("2. Check for IP address conflicts")
        click.echo("3. Ensure the network interface is available")
        
    elif error.details.get('error_type') == 'security_policy':
        click.echo("\nSecurity Policy Violation:")
        click.echo(f"• User: {error.details.get('user_id')}")
        click.echo(f"• Device: {error.details.get('device_id')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Verify your device meets security requirements")
        click.echo("2. Check if you have the necessary permissions")
        click.echo("3. Contact your administrator for policy details")
        
    elif error.details.get('error_type') == 'authentication':
        click.echo("\nAuthentication Failed:")
        click.echo(f"• User: {error.details.get('user_id')}")
        click.echo("\nAvailable Demo Accounts:")
        click.echo("1. developer@company.com / demo123")
        click.echo("2. admin@company.com / admin123")
        click.echo("3. user@company.com / user123")
        
    elif error.details.get('error_type') == 'config_error':
        click.echo("\nConfiguration Error:")
        click.echo(f"• Component: {error.details.get('component', 'unknown')}")
        click.echo(f"• Details: {error.details.get('details')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Check if WireGuard is properly installed")
        click.echo("2. Verify you have necessary permissions")
        click.echo("3. Try running with sudo if needed")
        click.echo("4. Check if /etc/wireguard directory exists and is writable")
        
    elif error.details.get('error_type') == 'peer_config':
        click.echo("\nPeer Configuration Error:")
        click.echo(f"• Details: {error.details.get('details')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Check WireGuard configuration permissions")
        click.echo("2. Verify peer configuration is valid")
        click.echo("3. Ensure no conflicting peer configurations exist")
        
    else:
        click.echo("\nUnexpected Error:")
        click.echo(f"• Type: {error.details.get('error_type', 'unknown')}")
        click.echo(f"• Details: {error.details.get('details', 'No additional details')}")
        click.echo("\nTroubleshooting Steps:")
        click.echo("1. Check system logs for detailed error messages")
        click.echo("2. Verify WireGuard installation")
        click.echo("3. Check file permissions")
        click.echo("4. Try running with sudo")
    
    # Show system requirements
    click.echo("\nSystem Requirements:")
    click.echo("• WireGuard must be installed")
    click.echo("• wg-quick must be available")
    click.echo("• Access to /etc/wireguard directory")
    
    # Show permissions info
    click.echo("\nPermission Requirements:")
    if error.details.get('error_type') in ['config_error', 'peer_config']:
        click.echo("This operation requires elevated privileges:")
        click.echo("1. Run with sudo:")
        click.echo("   sudo enterprise-vpn connect ...")
        click.echo("2. Or use --no-sudo flag for limited functionality:")
        click.echo("   enterprise-vpn connect --no-sudo ...")
    else:
        click.echo("• Run with --no-sudo flag for limited functionality")
        click.echo("• Some features may require sudo privileges")
    
    click.echo("\nAdditional Information:")
    click.echo("• Check logs in /var/log/syslog for WireGuard messages")
    click.echo("• Run 'wg show' to check interface status")
    click.echo("• Contact support if the issue persists")
    
    click.echo("─" * 50)

@click.group()
def cli():
    """Enterprise VPN client CLI.
    
    Demo Credentials:
    - Developer: developer@company.com / demo123
    - Admin: admin@company.com / admin123
    - User: user@company.com / user123
    """
    pass

@cli.command()
@click.option('--username', prompt=True, help='Username (e.g., developer@company.com)')
@click.option('--password', prompt='Password (demo: demo123)', hide_input=True, 
              help='Password (for demo: use demo123 for developer account)')
@click.option('--server', prompt=True, help='VPN server endpoint')
@click.option('--subnet', prompt=True, help='VPN subnet')
@click.option('--server-public-key', prompt=True, help='WireGuard server public key')
@click.option('--no-sudo', is_flag=True, help='Run without sudo (limited functionality)')
def connect(username: str, password: str, server: str, subnet: str, server_public_key: str, no_sudo: bool):
    """Connect to VPN."""
    try:
        click.echo("\nDemo Mode - Available Accounts:")
        click.echo("1. Developer: developer@company.com / demo123")
        click.echo("2. Admin: admin@company.com / admin123")
        click.echo("3. User: user@company.com / user123\n")
        
        # Setup configuration
        config_dir = Path(os.path.expanduser('~/.enterprise_vpn'))
        config = load_or_create_config(config_dir)
        
        # Save connection info for future use
        save_connection_info(config_dir, server, subnet)
        
        # Initialize components
        click.echo("Initializing components...")
        wireguard = WireGuardAdapter(server, subnet, mode=WireGuardMode.CLIENT, server_public_key=server_public_key)
        
        auth_provider = OktaAuthProvider(
            config['auth'].get('domain', 'your-okta-domain'),
            config['auth'].get('api_token', 'your-api-token')
        )
        
        validator = BeyondCorpValidator(
            config.get('security', {'max_risk_level': 'MEDIUM'})
        )
        
        monitor = ThreatMonitor()
        access_controller = AccessController()
        
        # Create connection manager
        connection_manager = ConnectionManager(
            wireguard=wireguard,
            validator=validator,
            threat_monitor=monitor,
            access_controller=access_controller
        )
        
        # Authenticate
        click.echo("Authenticating...")
        credentials = {'username': username, 'password': password}
        auth_context = auth_provider.authenticate(credentials)
        
        if not auth_context.authenticated:
            click.echo("❌ Authentication failed")
            click.echo("\nDemo Credentials:")
            click.echo("• Developer: developer@company.com / demo123")
            click.echo("• Admin: admin@company.com / admin123")
            click.echo("• User: user@company.com / user123")
            return
        
        click.echo("✓ Authentication successful")
        
        # Add device and context information
        auth_context.device_id = os.uname().nodename
        auth_context.context_data = {
            'source_ip': None,
            'location': 'unknown'
        }
        
        # Establish connection
        click.echo("\nEstablishing VPN connection...")
        if connection_manager.establish_connection(auth_context):
            click.echo("✓ VPN connection established")
            
            # Show connection details
            status = connection_manager.get_connection_status()
            if status.current_ip:
                click.echo(f"✓ Assigned IP: {status.current_ip}")
            
            # Show monitoring status
            try:
                metrics = monitor.collect_metrics()
                if not metrics.error_message:
                    click.echo("\nSystem Metrics:")
                    if metrics.cpu_usage > 0:
                        click.echo(f"✓ CPU Usage: {metrics.cpu_usage:.1f}%")
                    if metrics.memory_usage > 0:
                        click.echo(f"✓ Memory Usage: {metrics.memory_usage:.1f}%")
                    if metrics.warnings:
                        click.echo("\nWarnings:")
                        for warning in metrics.warnings:
                            click.echo(f"  ! {warning}")
            except Exception as e:
                if not no_sudo:
                    click.echo("\nNote: For full metrics, try running with sudo")
                click.echo(f"Limited metrics available: {str(e)}")
            
            click.echo("\nConnection Tips:")
            click.echo("• Use 'enterprise-vpn status' to check connection status")
            click.echo("• Use 'enterprise-vpn disconnect' to disconnect")
            
        else:
            click.echo("❌ Failed to establish VPN connection")
            
    except VPNConnectionError as e:
        display_connection_error(e)
    except Exception as e:
        click.echo(f"\n❌ Unexpected error: {str(e)}", err=True)
        click.echo("\nTroubleshooting:")
        click.echo("1. Check if WireGuard is installed")
        click.echo("2. Verify your system configuration")
        click.echo("3. Try running with --no-sudo flag")
        click.echo("4. Check system logs for details")

@cli.command()
def status():
    """Show VPN connection status."""
    try:
        config_dir = Path(os.path.expanduser('~/.enterprise_vpn'))
        
        # Load connection info
        try:
            with open(config_dir / 'connection.yaml') as f:
                connection_info = yaml.safe_load(f)
                
            if not connection_info or 'server' not in connection_info:
                click.echo("No active VPN configuration found")
                return
                
            # Initialize components
            wireguard = WireGuardAdapter(
                connection_info['server']['endpoint'],
                connection_info['server']['subnet']
            )
            
            config = load_or_create_config(config_dir)
            
            validator = BeyondCorpValidator(
                config.get('security', {'max_risk_level': 'MEDIUM'})
            )
            
            monitor = ThreatMonitor()
            access_controller = AccessController()
            
            connection_manager = ConnectionManager(
                wireguard=wireguard,
                validator=validator,
                threat_monitor=monitor,
                access_controller=access_controller
            )
            
            # Get status
            status = connection_manager.get_connection_status()
            
            click.echo("\nVPN Status:")
            click.echo(f"Connected: {'Yes' if status.is_connected else 'No'}")
            if status.is_connected:
                click.echo(f"IP Address: {status.current_ip}")
                click.echo(f"Connected Since: {status.connected_since}")
                if status.uptime:
                    click.echo(f"Uptime: {status.uptime:.0f} seconds")
                click.echo(f"Data Transferred: ↑{status.transfer_up/1024:.1f}KB ↓{status.transfer_down/1024:.1f}KB")
                if status.active_peers:
                    click.echo(f"Active Peers: {', '.join(status.active_peers)}")
            
            # Show monitoring status
            try:
                metrics = monitor.collect_metrics()
                if not metrics.error_message:
                    click.echo("\nSystem Metrics:")
                    click.echo(f"CPU Usage: {metrics.cpu_usage:.1f}%")
                    click.echo(f"Memory Usage: {metrics.memory_usage:.1f}%")
                    click.echo(f"Network Throughput: {metrics.network_throughput/1024:.1f} KB/s")
                    click.echo(f"Active Connections: {metrics.active_connections}")
                
                if metrics.warnings:
                    click.echo("\nWarnings:")
                    for warning in metrics.warnings:
                        click.echo(f"  ! {warning}")
            except Exception as e:
                click.echo(f"\nNote: Limited metrics available - {str(e)}")
            
        except FileNotFoundError:
            click.echo("Not connected. No active VPN configuration found.")
            
    except Exception as e:
        click.echo(f"Error checking status: {str(e)}", err=True)

@cli.command()
def disconnect():
    """Disconnect from VPN."""
    try:
        config_dir = Path(os.path.expanduser('~/.enterprise_vpn'))
        
        try:
            with open(config_dir / 'connection.yaml') as f:
                connection_info = yaml.safe_load(f)
                
            if not connection_info or 'server' not in connection_info:
                click.echo("No active VPN configuration found")
                return
                
            # Initialize components
            wireguard = WireGuardAdapter(
                connection_info['server']['endpoint'],
                connection_info['server']['subnet']
            )
            
            config = load_or_create_config(config_dir)
            
            validator = BeyondCorpValidator(
                config.get('security', {'max_risk_level': 'MEDIUM'})
            )
            
            monitor = ThreatMonitor()
            access_controller = AccessController()
            
            connection_manager = ConnectionManager(
                wireguard=wireguard,
                validator=validator,
                threat_monitor=monitor,
                access_controller=access_controller
            )
            
            if connection_manager.disconnect():
                click.echo("Disconnected from VPN")
                # Clean up connection info
                try:
                    os.remove(config_dir / 'connection.yaml')
                except Exception:
                    pass
            else:
                click.echo("Failed to disconnect")
                
        except FileNotFoundError:
            click.echo("No active VPN configuration found")
            
    except Exception as e:
        click.echo(f"Error disconnecting: {str(e)}", err=True)

if __name__ == '__main__':
    cli() 