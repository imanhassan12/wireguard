"""WireGuard adapter for enterprise VPN implementation."""

import os
import logging
import subprocess
import socket
import ipaddress
import time
import tempfile
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from wireguard import Server, Peer
from wireguard.utils.keys import generate_key, public_key
from wireguard.config import Config, ServerConfig
from .models import ConnectionStatus
from .exceptions import (
    WireGuardError,
    WireGuardConfigError,
    WireGuardConnectionError,
    WireGuardInterfaceError
)

class WireGuardMode(Enum):
    """Operating mode for WireGuard adapter."""
    SERVER = "server"
    CLIENT = "client"

class WireGuardAdapter:
    """Adapter for WireGuard functionality."""
    
    def __init__(self, server_endpoint: str, subnet: str, mode: WireGuardMode = WireGuardMode.CLIENT, server_public_key: str = None):
        """Initialize WireGuard adapter.
        
        Args:
            server_endpoint: Server endpoint (IP or hostname)
            subnet: VPN subnet (e.g., '10.0.0.0/24')
            mode: WireGuard operation mode (SERVER or CLIENT)
            server_public_key: Server's public key (required for client mode)
        """
        self.logger = logging.getLogger('wireguard')
        self.logger.info(f"Initializing WireGuard adapter in {mode.value} mode")
        self.mode = mode
        
        if not server_endpoint or not isinstance(server_endpoint, str):
            self.logger.error("Invalid server endpoint provided")
            raise WireGuardError("Invalid server endpoint")
        if not subnet or not isinstance(subnet, str):
            self.logger.error("Invalid subnet provided")
            raise WireGuardError("Invalid subnet")
            
        if mode == WireGuardMode.CLIENT and not server_public_key:
            raise WireGuardError("Server public key is required for client mode")
        
        self.endpoint = server_endpoint
        self.subnet = subnet
        self.server_public_key = server_public_key
        
        # Calculate server IP from subnet
        network = ipaddress.ip_network(subnet)
        self.server_ip = str(next(network.hosts()))  # First usable IP
        
        self.config_dir = "/etc/wireguard"
        
        try:
            # Check if WireGuard is installed
            self._check_wireguard_installation()
            
            # Check if we have necessary permissions
            self._check_permissions()
            
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
            # Calculate network details
            network = ipaddress.ip_network(self.subnet)
            self.server_ip = str(next(network.hosts()))
            
            # Use utun5 for server
            self.interface_name = 'utun5'
            
            # Clean up any existing interfaces
            try:
                self._run_sudo_command(['pkill', '-f', 'wireguard'])
                time.sleep(1)
                self._run_sudo_command(['rm', '-f', f'/var/run/wireguard/{self.interface_name}.sock'])
                time.sleep(1)
            except Exception:
                pass  # Ignore cleanup errors
            
            # Create the interface using wireguard-go
            try:
                self._run_sudo_command(['wireguard-go', self.interface_name], check=True)
                time.sleep(2)  # Wait for interface to be ready
            except Exception as e:
                self.logger.error(f"Error creating interface: {str(e)}")
                raise
            
            # Configure the interface
            try:
                # Generate keys
                private_key = generate_key()
                
                # Save private key to a temporary file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_file.write(private_key)
                    temp_file.flush()
                    
                    # Set private key and port
                    self._run_sudo_command(['wg', 'set', self.interface_name, 
                                       'private-key', temp_file.name,
                                       'listen-port', '51820'], check=True)
                    
                os.unlink(temp_file.name)
                time.sleep(1)  # Wait for configuration
            except Exception as e:
                self.logger.error(f"Error configuring interface: {str(e)}")
                raise
            
            # Set up IP address and routing
            try:
                # First bring up the interface
                self._run_sudo_command(['ifconfig', self.interface_name, 'up'], check=True)
                
                # Then set the IP address (macOS syntax)
                self._run_sudo_command(['ifconfig', self.interface_name, self.server_ip, 
                                   self.server_ip, 'netmask', '255.255.255.0'], check=True)
                
                # Enable IP forwarding and NAT
                self._run_sudo_command(['sysctl', '-w', 'net.inet.ip.forwarding=1'], check=True)
                
                # Configure PF for NAT
                pf_rules = f"""
# Enable NAT
nat on en0 from {self.subnet} to any -> (en0)

# Allow all traffic
pass in all
pass out all

# Allow WireGuard traffic
pass in quick proto udp from any to any port 51820
pass in quick on {self.interface_name} all
pass out quick on {self.interface_name} all
"""
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_file.write(pf_rules)
                    temp_file.flush()
                    self._run_sudo_command(['pfctl', '-F', 'all'], check=True)  # Flush all rules
                    self._run_sudo_command(['pfctl', '-f', temp_file.name], check=True)
                os.unlink(temp_file.name)
                
                # Enable PF
                try:
                    self._run_sudo_command(['pfctl', '-e'], check=True)
                except Exception:
                    pass  # Ignore if already enabled
                
            except Exception as e:
                self.logger.error(f"Error setting up networking: {str(e)}")
                raise
            
            # Verify interface is up
            try:
                wg_result = self._run_sudo_command(['wg', 'show', self.interface_name])
                if wg_result.returncode != 0:
                    raise WireGuardError(f"Interface verification failed: {wg_result.stderr}")
                self.logger.info(f"Interface configuration:\n{wg_result.stdout}")
            except Exception as e:
                self.logger.error(f"Error verifying interface: {str(e)}")
                raise
            
            # Create server instance for management
            server = Server(
                description="Enterprise VPN Server",
                subnet=self.subnet,
                address=self.server_ip,
                endpoint=self.endpoint,
                port=51820,
                interface=self.interface_name,
                save_config=True
            )
            
            return server
            
        except Exception as e:
            raise WireGuardError(f"Server initialization failed: {str(e)}")
    
    def _initialize_client(self) -> Server:
        """Initialize client configuration."""
        try:
            # Calculate network details
            network = ipaddress.ip_network(self.subnet)
            client_ip = str(list(network.hosts())[1])  # First IP is server
            
            # Use utun10 for client
            self.interface_name = 'utun10'
            
            # Clean up any existing interfaces
            try:
                self._run_sudo_command(['pkill', '-f', 'wireguard'])
                time.sleep(1)
                self._run_sudo_command(['rm', '-f', f'/var/run/wireguard/{self.interface_name}.sock'])
                time.sleep(1)
            except Exception:
                pass  # Ignore cleanup errors
            
            # Create the interface using wireguard-go
            try:
                self._run_sudo_command(['wireguard-go', self.interface_name], check=True)
                time.sleep(2)  # Wait for interface to be ready
            except Exception as e:
                self.logger.error(f"Error creating interface: {str(e)}")
                raise
            
            # Configure the interface
            try:
                # Generate keys
                private_key = generate_key()
                
                # Save private key to a temporary file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                    temp_file.write(private_key)
                    temp_file.flush()
                    
                    # Set private key
                    self._run_sudo_command(['wg', 'set', self.interface_name, 
                                       'private-key', temp_file.name], check=True)
                    
                os.unlink(temp_file.name)
                
                # Set peer configuration
                self._run_sudo_command(['wg', 'set', self.interface_name,
                                   'peer', self.server_public_key,
                                   'allowed-ips', self.subnet,
                                   'endpoint', f'{self.endpoint}:51820',
                                   'persistent-keepalive', '25'], check=True)
                
                time.sleep(1)  # Wait for configuration
            except Exception as e:
                self.logger.error(f"Error configuring interface: {str(e)}")
                raise
            
            # Set up IP address and routing
            try:
                # First bring up the interface
                self._run_sudo_command(['ifconfig', self.interface_name, 'up'], check=True)
                
                # Then set the IP address (macOS syntax)
                self._run_sudo_command(['ifconfig', self.interface_name, client_ip, 
                                   client_ip, 'netmask', '255.255.255.0'], check=True)
                
                # Add route for VPN subnet
                self._run_sudo_command(['route', 'add', '-net', self.subnet, '-interface', self.interface_name], check=True)
            except Exception as e:
                self.logger.error(f"Error setting up networking: {str(e)}")
                raise
            
            # Verify interface is up
            try:
                wg_result = self._run_sudo_command(['wg', 'show', self.interface_name])
                if wg_result.returncode != 0:
                    raise WireGuardError(f"Interface verification failed: {wg_result.stderr}")
                self.logger.info(f"Interface configuration:\n{wg_result.stdout}")
            except Exception as e:
                self.logger.error(f"Error verifying interface: {str(e)}")
                raise
            
            # Create client instance
            client = Server(
                description="Enterprise VPN Client",
                subnet=self.subnet,
                address=client_ip,
                endpoint=self.endpoint,
                port=51820,
                interface=self.interface_name,
                save_config=True
            )
            
            return client
            
        except Exception as e:
            raise WireGuardError(f"Client initialization failed: {str(e)}")
    
    def _run_sudo_command(self, command: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """Run a command with sudo.
        
        Args:
            command: Command and arguments as list
            check: Whether to check return code
            
        Returns:
            CompletedProcess instance
        """
        # Create a temporary file to store the password
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("5791346825\n")
            temp_file.flush()
            
            try:
                # Use the password file with sudo
                result = subprocess.run(['sudo', '-S'] + command,
                                   stdin=open(temp_file.name, 'r'),
                                   capture_output=True,
                                   text=True,
                                   check=check)
                return result
            finally:
                # Clean up the temporary file
                os.unlink(temp_file.name)
    
    def _check_server_connectivity(self, endpoint: str, port: int = 51820) -> bool:
        """Check if the server is accessible.
        
        Args:
            endpoint: Server endpoint to check
            port: Server port to check (default: 51820)
            
        Returns:
            bool: True if server is accessible, False otherwise
        """
        try:
            # If endpoint is localhost, check if the port is listening
            if endpoint in ['localhost', '127.0.0.1']:
                try:
                    result = self._run_sudo_command(['lsof', '-i', f':{port}'])
                    return 'wireguard' in result.stdout.lower()
                except Exception:
                    return False
            
            # For remote endpoints, try to establish a UDP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            try:
                sock.connect((endpoint, port))
                return True
            except (socket.timeout, socket.error):
                return False
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.error(f"Error checking server connectivity: {str(e)}")
            return False
    
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
    
    def validate_config(self) -> bool:
        """Validate WireGuard configuration.
        
        Returns:
            bool: True if configuration is valid
            
        Raises:
            WireGuardError: If configuration is invalid
        """
        try:
            # Check if config directory exists
            if not os.path.exists(self.config_dir):
                raise WireGuardError("WireGuard configuration directory not found")
            
            # Check if we have necessary permissions
            if not os.access(self.config_dir, os.W_OK):
                raise WireGuardError("No write permission for WireGuard configuration directory")
            
            # Check if WireGuard is installed
            result = subprocess.run(['which', 'wg'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            if result.returncode != 0:
                raise WireGuardError("WireGuard (wg) command not found")
            
            # Check if wg-quick is available
            result = subprocess.run(['which', 'wg-quick'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            if result.returncode != 0:
                raise WireGuardError("wg-quick command not found")
            
            # Validate subnet format
            try:
                ipaddress.ip_network(self.subnet)
            except ValueError as e:
                raise WireGuardError(f"Invalid subnet format: {str(e)}")
            
            # Validate endpoint format
            if not self.endpoint:
                raise WireGuardError("Server endpoint not configured")
            
            # If config exists, check if it's readable
            if os.path.exists(self.config_path):
                if not os.access(self.config_path, os.R_OK):
                    raise WireGuardError("Cannot read existing WireGuard configuration")
            
            return True
            
        except WireGuardError:
            raise
        except Exception as e:
            raise WireGuardError(f"Configuration validation failed: {str(e)}")
            
    def get_connection_status(self) -> ConnectionStatus:
        """Get current connection status.
        
        Returns:
            ConnectionStatus object
        """
        try:
            # Check if interface exists
            result = subprocess.run(['wg', 'show', 'wg0'], 
                                capture_output=True, 
                                text=True, 
                                check=False)
            
            is_connected = result.returncode == 0
            
            if is_connected:
                # Parse wg show output for more details
                lines = result.stdout.split('\n')
                transfer_up = 0
                transfer_down = 0
                peers = []
                
                for line in lines:
                    if 'transfer:' in line.lower():
                        parts = line.split()
                        if len(parts) >= 4:
                            transfer_up = int(parts[1].replace('B', ''))
                            transfer_down = int(parts[3].replace('B', ''))
                    elif 'peer:' in line.lower():
                        peers.append(line.split(':')[1].strip())
                
                return ConnectionStatus(
                    is_connected=True,
                    connected_since=self._connection_status.connected_since,
                    current_ip=self._connection_status.current_ip,
                    transfer_up=transfer_up,
                    transfer_down=transfer_down,
                    active_peers=peers
                )
            
            return ConnectionStatus(
                is_connected=False,
                connected_since=None,
                current_ip=None
            )
            
        except Exception as e:
            self.logger.error(f"Error getting connection status: {str(e)}")
            return ConnectionStatus(
                is_connected=False,
                connected_since=None,
                current_ip=None
            )
    
    def connect(self, server: str, subnet: str) -> bool:
        """Connect to a WireGuard server.
        
        Args:
            server (str): Server address
            subnet (str): Subnet to use
            
        Returns:
            bool: True if connection was successful
            
        Raises:
            WireGuardError: If connection failed
        """
        if self.is_server_mode:
            raise WireGuardError("Cannot connect in server mode")
            
        # Check server connectivity first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((server, 51820))
            sock.close()
            
            if result != 0:
                raise WireGuardError(f"Server port not accessible (Error code: {result})")
                
        except Exception as e:
            raise WireGuardError(f"Failed to check server connectivity: {str(e)}")
            
        # Generate client config
        self.client.generate_config(server, subnet)
        
        # Start the interface
        self.start_interface()
        
        # Wait for connection to establish
        time.sleep(2)
        
        # Verify connection
        try:
            result = subprocess.run(['wg', 'show', 'wg0'], 
                                capture_output=True, 
                                text=True, 
                                check=True)
            if "latest handshake" not in result.stdout:
                self.stop_interface()
                raise WireGuardError("No handshake detected with server")
                
            return True
            
        except subprocess.CalledProcessError as e:
            self.stop_interface()
            raise WireGuardError(f"Failed to verify connection: {e.stderr}")
            
        except Exception as e:
            self.stop_interface()
            raise WireGuardError(f"Connection failed: {str(e)}")
    
    def _cleanup_interface(self, interface: str) -> None:
        """Clean up an interface thoroughly.
        
        Args:
            interface: The interface name to clean up
        """
        try:
            # Try to bring down interface using wg-quick
            self._run_sudo_command(['wg-quick', 'down', interface])
            
            # Try to bring down interface using ifconfig
            self._run_sudo_command(['ifconfig', interface, 'down'])
            
            # Remove any existing socket files
            socket_path = f"/var/run/wireguard/{interface}.sock"
            if os.path.exists(socket_path):
                self._run_sudo_command(['rm', socket_path])
            
            # Remove any existing name files
            name_path = f"/var/run/wireguard/{interface}.name"
            if os.path.exists(name_path):
                self._run_sudo_command(['rm', name_path])
            
            time.sleep(1)  # Wait for cleanup
            
        except Exception as e:
            self.logger.warning(f"Error during cleanup of {interface}: {str(e)}")
    
    def start_interface(self) -> None:
        """Start the WireGuard interface using direct configuration."""
        try:
            # Use the already determined interface name
            interface = self.interface_name
            
            # Clean up the interface first
            self._cleanup_interface(interface)
            
            # Verify WireGuard configuration
            try:
                wg_result = self._run_sudo_command(['wg', 'show', interface])
            except Exception as e:
                self.logger.error(f"Error verifying interface: {str(e)}, type: {type(e)}")
                raise
            
            if wg_result.returncode != 0:
                self.logger.error(f"WireGuard show output: {wg_result.stderr}")
                raise WireGuardInterfaceError(f"Interface {interface} not properly configured")
            
            self.logger.info(f"WireGuard interface configuration:\n{wg_result.stdout}")
            self.logger.info("Interface verification successful")
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to manage interface: {e.stderr if hasattr(e, 'stderr') else str(e)}"
            self.logger.error(error_msg)
            raise WireGuardInterfaceError(error_msg)
        except Exception as e:
            error_msg = f"Interface management failed: {str(e)}, type: {type(e)}"
            self.logger.error(error_msg)
            raise WireGuardInterfaceError(error_msg)
    
    def stop_interface(self) -> None:
        """Stop the WireGuard interface.
        
        Raises:
            WireGuardInterfaceError: If interface cannot be stopped
        """
        try:
            # Try to find active interface
            interfaces_to_check = ['utun6', 'utun7', 'utun8', 'utun9'] if self.mode == WireGuardMode.SERVER else ['utun10', 'utun11']
            
            for interface in interfaces_to_check:
                try:
                    # Check if interface exists
                    ifconfig_result = subprocess.run(['ifconfig', interface],
                                                capture_output=True,
                                                text=True,
                                                check=False)
                    
                    if ifconfig_result.returncode == 0:
                        # Interface exists, try to stop it
                        self.logger.info(f"Found active interface: {interface}")
                        
                        # Try manual cleanup first
                        self._cleanup_interface(interface)
                        
                        # Try wg-quick if config exists
                        config_path = os.path.join(self.config_dir, f"{interface}.conf")
                        if os.path.exists(config_path):
                            subprocess.run(['sudo', 'wg-quick', 'down', config_path],
                                      capture_output=True,
                                      text=True,
                                      check=False)
                        
                        self.logger.info(f"Stopped WireGuard interface: {interface}")
                        
                except Exception as e:
                    self.logger.warning(f"Error checking/stopping interface {interface}: {str(e)}")
                    continue
            
            # Clean up any configuration files
            config_files = [f for f in os.listdir(self.config_dir) if f.endswith('.conf')]
            for config_file in config_files:
                try:
                    os.remove(os.path.join(self.config_dir, config_file))
                except Exception as e:
                    self.logger.warning(f"Failed to remove config file {config_file}: {str(e)}")
            
        except Exception as e:
            raise WireGuardInterfaceError(f"Failed to stop interface: {str(e)}")
    
    # ... (keep other methods) ...