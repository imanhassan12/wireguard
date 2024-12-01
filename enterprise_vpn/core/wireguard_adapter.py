"""WireGuard adapter for enterprise VPN implementation."""

import os
import logging
import subprocess
import socket
import ipaddress
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from wireguard import Server, Peer
from wireguard.utils.keys import generate_key, public_key
from wireguard.config import Config
from .models import ConnectionStatus

class WireGuardError(Exception):
    """Custom exception for WireGuard-related errors."""
    pass

class WireGuardMode(Enum):
    """Operating mode for WireGuard adapter."""
    SERVER = "server"
    CLIENT = "client"

class WireGuardAdapter:
    """Adapter for WireGuard functionality."""
    
    def __init__(self, server_endpoint: str, subnet: str, mode: WireGuardMode = WireGuardMode.CLIENT):
        """Initialize WireGuard adapter."""
        self.logger = logging.getLogger('wireguard')
        self.logger.info(f"Initializing WireGuard adapter in {mode.value} mode")
        self.mode = mode
        
        if not server_endpoint or not isinstance(server_endpoint, str):
            self.logger.error("Invalid server endpoint provided")
            raise WireGuardError("Invalid server endpoint")
        if not subnet or not isinstance(subnet, str):
            self.logger.error("Invalid subnet provided")
            raise WireGuardError("Invalid subnet")
            
        try:
            # Check if WireGuard is installed
            self._check_wireguard_installation()
            
            # Check if we have necessary permissions
            self._check_permissions()
            
            # Set up base configuration
            self.endpoint = server_endpoint
            self.subnet = subnet
            
            # Calculate server IP from subnet
            network = ipaddress.ip_network(subnet)
            self.server_ip = str(next(network.hosts()))  # First usable IP
            
            self.config_dir = "/etc/wireguard"
            
            if mode == WireGuardMode.SERVER:
                # Server-specific initialization
                self.config_path = os.path.join(self.config_dir, "wg0.conf")
                self.server = self._initialize_server()
            else:
                # Client-specific initialization
                self.config_path = os.path.join(self.config_dir, f"client_{socket.gethostname()}.conf")
                self.server = self._initialize_client()
                
            self._connection_status = ConnectionStatus(
                is_connected=False,
                connected_since=None,
                current_ip=None
            )
            
            self.logger.info(f"WireGuard adapter initialized successfully in {mode.value} mode")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize WireGuard: {str(e)}")
            raise WireGuardError(f"Failed to initialize WireGuard: {str(e)}")
    
    def _check_wireguard_installation(self) -> None:
        """Check if WireGuard is installed and available.
        
        Raises:
            WireGuardError: If WireGuard is not installed or not accessible
        """
        try:
            # Check for wg command
            result = subprocess.run(['which', 'wg'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            
            if result.returncode != 0:
                raise WireGuardError(
                    "WireGuard (wg) command not found. Please install WireGuard first."
                )
            
            # Check for wg-quick
            result = subprocess.run(['which', 'wg-quick'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            
            if result.returncode != 0:
                raise WireGuardError(
                    "wg-quick command not found. Please install WireGuard tools."
                )
            
            # Try to get WireGuard version
            result = subprocess.run(['wg', '--version'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            
            if result.returncode == 0:
                self.logger.info(f"Found WireGuard: {result.stdout.strip()}")
            else:
                raise WireGuardError("Unable to determine WireGuard version")
                
        except FileNotFoundError:
            raise WireGuardError("Unable to check WireGuard installation")
    
    def _check_permissions(self) -> None:
        """Check if we have necessary permissions.
        
        Raises:
            WireGuardError: If required permissions are not available
        """
        try:
            # Check if we can access /etc/wireguard
            wireguard_dir = "/etc/wireguard"
            if not os.path.exists(wireguard_dir):
                try:
                    os.makedirs(wireguard_dir, mode=0o700)
                    self.logger.info(f"Created {wireguard_dir} directory")
                except PermissionError:
                    raise WireGuardError(
                        f"No permission to create {wireguard_dir}. "
                        "Try running with sudo."
                    )
            
            # Check if we can write to the directory
            test_file = os.path.join(wireguard_dir, "test_permission")
            try:
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
            except PermissionError:
                raise WireGuardError(
                    f"No permission to write to {wireguard_dir}. "
                    "Try running with sudo."
                )
            
            # Check if we can run wg with sudo
            if os.geteuid() != 0:
                raise WireGuardError(
                    "Root privileges required. Please run with sudo."
                )
                
        except Exception as e:
            if not isinstance(e, WireGuardError):
                raise WireGuardError(f"Permission check failed: {str(e)}")
            raise
    
    def _initialize_server(self) -> Server:
        """Initialize server configuration."""
        try:
            # Generate server keys
            server_private = generate_key()
            server_public = public_key(server_private)
            
            # Create server instance
            server = Server(
                description="Enterprise VPN Server",
                subnet=self.subnet,
                address=self.server_ip,
                endpoint=self.endpoint,
                port=51820,
                private_key=server_private,
                public_key=server_public,
                allowed_ips=[self.subnet]
            )
            
            # Ensure config directory exists
            os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
            
            # Write initial configuration if it doesn't exist
            if not os.path.exists(self.config_path):
                self.logger.info(f"Creating initial server configuration at {self.config_path}")
                
                # Create basic server config
                config = Config()
                config.add_interface({
                    'PrivateKey': server_private,
                    'Address': f"{self.server_ip}/{network.prefixlen}",
                    'ListenPort': 51820
                })
                
                # Add initial peer config
                config.add_peer({
                    'PublicKey': server_public,
                    'AllowedIPs': self.subnet
                })
                
                # Write config to file
                with open(self.config_path, 'w') as f:
                    f.write(str(config))
                
                # Set proper permissions
                os.chmod(self.config_path, 0o600)
                
                self.logger.info("Server configuration created successfully")
            else:
                self.logger.info(f"Using existing server configuration at {self.config_path}")
                # Load existing config
                config = Config.from_file(self.config_path)
                server.config = config
            
            return server
            
        except Exception as e:
            raise WireGuardError(f"Server initialization failed: {str(e)}")
    
    def _initialize_client(self) -> Server:
        """Initialize client configuration."""
        try:
            # Generate client keys
            client_private = generate_key()
            client_public = public_key(client_private)
            
            # Calculate client IP (second usable IP in subnet)
            network = ipaddress.ip_network(self.subnet)
            client_ip = str(list(network.hosts())[1])
            
            # Create client instance
            server = Server(
                description="Enterprise VPN Client",
                subnet=self.subnet,
                address=client_ip,
                endpoint=self.endpoint,
                port=51820,
                private_key=client_private,
                public_key=client_public,
                allowed_ips=[self.subnet]
            )
            
            # Ensure config directory exists
            os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
            
            return server
            
        except Exception as e:
            raise WireGuardError(f"Client initialization failed: {str(e)}")
    
    def check_server_connectivity(self) -> Tuple[bool, Optional[str]]:
        """Check if server is reachable."""
        try:
            # Try to resolve hostname
            try:
                server_ip = socket.gethostbyname(self.endpoint)
            except socket.gaierror:
                return False, f"Could not resolve hostname: {self.endpoint}"
            
            # Try to connect to WireGuard port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.connect((server_ip, 51820))
                sock.close()
                return True, None
            except (socket.timeout, ConnectionRefusedError):
                return False, f"Could not connect to {self.endpoint}:51820"
            except Exception as e:
                return False, f"Connection error: {str(e)}"
                
        except Exception as e:
            return False, f"Connectivity check failed: {str(e)}"
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        try:
            info = {
                'endpoint': self.endpoint,
                'subnet': self.subnet,
                'config_path': self.config_path,
                'mode': self.mode.value,
                'status': 'initialized'
            }
            
            # Add server-specific information
            if self.server:
                info.update({
                    'public_key': self.server.public_key,
                    'interface': 'wg0' if self.mode == WireGuardMode.SERVER else None
                })
            
            # Check interface status
            if self.mode == WireGuardMode.SERVER:
                try:
                    result = subprocess.run(['wg', 'show', 'wg0'], 
                                         capture_output=True, 
                                         text=True, 
                                         check=False)
                    info['interface_active'] = result.returncode == 0
                except Exception:
                    info['interface_active'] = False
            
            return info
            
        except Exception as e:
            self.logger.error(f"Failed to get server info: {str(e)}")
            # Return minimal information on error
            return {
                'endpoint': self.endpoint,
                'subnet': self.subnet,
                'error': str(e)
            }
    
    # ... (keep other methods) ...