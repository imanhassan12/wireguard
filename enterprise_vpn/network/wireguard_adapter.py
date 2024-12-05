"""WireGuard network adapter implementation."""

import os
import subprocess
import logging
import tempfile
import ipaddress
import socket
from typing import Optional, Dict, Any
from pathlib import Path

class WireGuardAdapter:
    """WireGuard network adapter implementation."""
    
    def __init__(self, config: dict):
        """Initialize WireGuard adapter.
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger('wireguard')
        self.config = config
        self.interface_name = config.get('interface', 'wg0')
        self.endpoint = config.get('endpoint', 'localhost')
        self.subnet = config.get('subnet', '10.0.0.0/24')
        self.config_path = None
        self.is_initialized = False
        
    def initialize(self) -> None:
        """Initialize WireGuard interface."""
        try:
            # Check if WireGuard is installed
            self._check_wireguard_installed()
            
            # Create temporary config file instead of writing directly to /etc/wireguard
            temp_dir = tempfile.mkdtemp()
            self.config_path = os.path.join(temp_dir, f"{self.interface_name}.conf")
            
            # Generate WireGuard config
            config_content = self._generate_config()
            
            # Write config to temporary file
            with open(self.config_path, 'w') as f:
                f.write(config_content)
            
            self.logger.info(f"WireGuard config written to {self.config_path}")
            self.is_initialized = True
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize WireGuard: {str(e)}")
    
    def start(self) -> None:
        """Start WireGuard interface."""
        if not self.is_initialized:
            raise RuntimeError("WireGuard adapter not initialized")
            
        try:
            # Use wg-quick up with sudo
            cmd = ['sudo', 'wg-quick', 'up', self.config_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Log the actual config file content
                config_content = subprocess.run(
                    ['sudo', 'cat', self.config_path],
                    capture_output=True,
                    text=True
                ).stdout
                self.logger.error(f"Config file content:\n{config_content}")
                
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                raise RuntimeError(f"Failed to start WireGuard: {error_msg}")
                
            self.logger.info(f"WireGuard interface {self.interface_name} started")
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to start WireGuard: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error starting WireGuard: {str(e)}")
    
    def stop(self) -> None:
        """Stop WireGuard interface."""
        if not self.is_initialized:
            return
            
        try:
            # Use wg-quick down with sudo
            cmd = ['sudo', 'wg-quick', 'down', self.config_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.warning(f"Failed to stop WireGuard: {result.stderr}")
            
            # Clean up config file
            if self.config_path and os.path.exists(self.config_path):
                subprocess.run(
                    ['sudo', 'rm', '-f', self.config_path],
                    check=True,
                    capture_output=True,
                    text=True
                )
            
            self.logger.info(f"WireGuard interface {self.interface_name} stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping WireGuard: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get WireGuard interface status.
        
        Returns:
            Dict containing interface status
        """
        if not self.is_initialized:
            return {'status': 'not_initialized'}
            
        try:
            cmd = ['sudo', 'wg', 'show', self.interface_name]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {
                    'status': 'running',
                    'details': result.stdout
                }
            else:
                return {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _check_wireguard_installed(self) -> None:
        """Check if WireGuard is installed."""
        try:
            # Check for wg command
            subprocess.run(['which', 'wg'], check=True, capture_output=True)
            # Check for wg-quick command
            subprocess.run(['which', 'wg-quick'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "WireGuard not found. Please install WireGuard:\n"
                "- macOS: brew install wireguard-tools\n"
                "- Linux: sudo apt install wireguard\n"
                "- Windows: Download from wireguard.com"
            )
    
    def _generate_config(self) -> str:
        """Generate WireGuard configuration.
        
        Returns:
            str: WireGuard configuration content
        """
        try:
            # Get configuration values
            private_key = self.config.get('private_key', '').strip()
            public_key = self.config.get('public_key', '').strip()
            endpoint = self.config.get('endpoint', self.endpoint).strip()
            allowed_ips = self.config.get('allowed_ips', '0.0.0.0/0').strip()
            listen_port = str(self.config.get('listen_port', 51820)).strip()
            
            # Basic validation
            if not private_key:
                raise ValueError("Private key is required")
            if not public_key:
                raise ValueError("Public key is required")
            
            # Calculate client IP (second usable IP in subnet)
            network = ipaddress.ip_network(self.subnet)
            client_ip = str(list(network.hosts())[1])
            
            # Log configuration parameters (without private key)
            self.logger.debug("Configuration parameters:")
            self.logger.debug(f"- Interface: {self.interface_name}")
            self.logger.debug(f"- Endpoint: {endpoint}")
            self.logger.debug(f"- Client IP: {client_ip}")
            self.logger.debug(f"- Listen Port: {listen_port}")
            self.logger.debug(f"- Public Key: {public_key}")
            
            # Create config lines with minimal format
            config = f"""[Interface]
Address={client_ip}/24
PrivateKey={private_key}
DNS=8.8.8.8

[Peer]
PublicKey={public_key}
AllowedIPs={allowed_ips}
Endpoint={endpoint}:{listen_port}
PersistentKeepalive=25
"""
            
            # Write config directly to /etc/wireguard
            self.config_path = f"/etc/wireguard/{self.interface_name}.conf"
            
            # Use sudo to write the config
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(config)
                temp_path = temp_file.name
            
            # Copy the temp file to /etc/wireguard with sudo
            subprocess.run(
                ['sudo', 'cp', temp_path, self.config_path],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Set proper permissions
            subprocess.run(
                ['sudo', 'chmod', '600', self.config_path],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Clean up temp file
            os.unlink(temp_path)
            
            return config
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate WireGuard config: {str(e)}")
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.stop()
    
    def check_server_connectivity(self, server_address, port):
        # Add timeout to prevent hanging
        try:
            sock = socket.create_connection((server_address, port), timeout=5)
            sock.close()
            return True
        except (socket.timeout, socket.error) as e:
            self.logger.error(f"Server connectivity check failed: {str(e)}")
            return False
    
    def connect(self, server_address, server_port, server_public_key):
        if not self.check_server_connectivity(server_address, server_port):
            raise ConnectionError(
                f"Cannot connect to VPN server at {server_address}:{server_port}. "
                "Please verify:\n"
                "1. The server address is correct\n"
                "2. The server is running and accessible\n"
                "3. No firewalls are blocking port {server_port}"
            )
        
        # Existing connection logic... 