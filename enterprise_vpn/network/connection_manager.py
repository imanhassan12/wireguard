"""Connection manager for enterprise VPN."""

from typing import Optional, Dict, Any, Tuple
from datetime import datetime
import socket
import logging
from ..core import ConnectionStatus
from ..core.wireguard_adapter import WireGuardAdapter, WireGuardError
from ..security.auth import AuthenticationContext
from ..security.beyondcorp import BeyondCorpValidator
from ..management.threat_monitoring import ThreatMonitor
from ..network.access_control import AccessController
import subprocess

class VPNConnectionError(Exception):
    """Custom exception for VPN connection errors."""
    def __init__(self, message: str, details: Dict[str, Any]):
        super().__init__(message)
        self.details = details

class ConnectionManager:
    """Manages VPN connections with enhanced security."""
    
    def __init__(self, 
                 wireguard: WireGuardAdapter,
                 validator: BeyondCorpValidator,
                 threat_monitor: ThreatMonitor,
                 access_controller: AccessController):
        """Initialize connection manager."""
        self.wireguard = wireguard
        self.validator = validator
        self.threat_monitor = threat_monitor
        self.access_controller = access_controller
        self._current_session: Optional[Dict[str, Any]] = None
        self.logger = logging.getLogger('vpn_connection')
        
        # Validate initial configuration
        try:
            self.wireguard.validate_config()
        except WireGuardError as e:
            raise VPNConnectionError("Invalid WireGuard configuration", {
                'error_type': 'config_error',
                'details': str(e),
                'component': 'wireguard'
            })
    
    def check_server_availability(self) -> Tuple[bool, Optional[str]]:
        """Check if VPN server is reachable."""
        try:
            server_info = self.wireguard.get_server_info()
            if not server_info['endpoint']:
                return False, "Server endpoint not configured"
            
            # Try to resolve the hostname
            try:
                server_ip = socket.gethostbyname(server_info['endpoint'])
            except socket.gaierror:
                return False, f"Could not resolve hostname: {server_info['endpoint']}"
            
            # Try to connect to the server
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((server_ip, 51820))
                sock.close()
                
                if result == 0:
                    return True, None
                else:
                    return False, f"Server port not accessible (Error code: {result})"
            except socket.timeout:
                return False, "Connection attempt timed out"
            except Exception as e:
                return False, f"Network error: {str(e)}"
                
        except Exception as e:
            return False, f"Server check failed: {str(e)}"
    
    def validate_network_config(self) -> Tuple[bool, Optional[str]]:
        """Validate network configuration."""
        try:
            server_info = self.wireguard.get_server_info()
            
            # Check subnet configuration
            if not server_info['subnet']:
                return False, "Subnet not configured"
            
            # Validate server configuration
            try:
                self.wireguard.validate_config()
            except WireGuardError as e:
                return False, str(e)
            
            # Check for IP conflicts
            if self._check_ip_conflicts():
                return False, "IP address conflict detected"
            
            return True, None
            
        except Exception as e:
            return False, f"Network configuration error: {str(e)}"
    
    def _check_ip_conflicts(self) -> bool:
        """Check for IP address conflicts."""
        # TODO: Implement actual IP conflict checking
        return False
    
    def _check_server_connectivity(self, endpoint: str, port: int = 51820) -> bool:
        """Check if the server is accessible.
        
        Args:
            endpoint: Server endpoint to check
            port: Server port to check
            
        Returns:
            bool: True if server is accessible, False otherwise
        """
        try:
            # If endpoint is localhost, check if the port is listening
            if endpoint in ['localhost', '127.0.0.1']:
                try:
                    result = subprocess.run(['sudo', 'lsof', '-i', f':{port}'],
                                       capture_output=True,
                                       text=True)
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
    
    def establish_connection(self, auth_context: AuthenticationContext) -> bool:
        """Establish VPN connection.
        
        Args:
            auth_context: Authentication context
            
        Returns:
            bool: True if connection established successfully
            
        Raises:
            VPNConnectionError: If connection fails
        """
        try:
            # Validate security requirements
            if not self.validator.validate_device(auth_context.device_id):
                raise VPNConnectionError(
                    "Device security validation failed",
                    {
                        'error_type': 'security_policy',
                        'device_id': auth_context.device_id,
                        'user_id': auth_context.user_id
                    }
                )
            
            # Check server connectivity
            server_endpoint = self.wireguard.endpoint
            if not self.wireguard._check_server_connectivity(server_endpoint):
                raise VPNConnectionError(
                    "Server connectivity check failed",
                    {
                        'error_type': 'server_connectivity',
                        'server': server_endpoint,
                        'details': 'Server port not accessible'
                    }
                )
            
            # Start monitoring
            self.threat_monitor.start_monitoring()
            
            # Initialize connection
            try:
                self.wireguard.start_interface()
            except Exception as e:
                raise VPNConnectionError(
                    f"Failed to initialize connection: {str(e)}",
                    {
                        'error_type': 'config_error',
                        'component': 'wireguard',
                        'details': str(e)
                    }
                )
            
            # Store session information
            self._current_session = {
                'auth_context': auth_context,
                'start_time': datetime.now()
            }
            
            # Update connection status
            if not hasattr(self, '_connection_status'):
                self._connection_status = ConnectionStatus(
                    is_connected=False,
                    connected_since=None,
                    current_ip=None,
                    transfer_up=0,
                    transfer_down=0,
                    active_peers=[]
                )
            
            self._connection_status = ConnectionStatus(
                is_connected=True,
                connected_since=datetime.now(),
                current_ip=self.wireguard.server_ip if self.wireguard.mode == WireGuardMode.SERVER else None,
                transfer_up=0,
                transfer_down=0,
                active_peers=[]
            )
            
            return True
            
        except VPNConnectionError:
            raise
        except Exception as e:
            raise VPNConnectionError(
                f"Unexpected error: {str(e)}",
                {
                    'error_type': 'unknown',
                    'details': str(e)
                }
            )
    
    def check_access(self, resource: str) -> bool:
        """Check if current session has access to resource.
        
        Args:
            resource: Resource identifier
            
        Returns:
            bool indicating if access is allowed
        """
        if not self._current_session:
            return False
            
        auth_context = self._current_session['auth_context']
        context_data = {
            'timestamp': datetime.now(),
            'source_ip': auth_context.context_data.get('source_ip'),
            'resource': resource
        }
        
        # Check access policy
        decision = self.access_controller.check_access(
            auth_context.user_id,
            resource,
            context_data
        )
        
        # Monitor access attempts
        if not decision.allowed:
            self.threat_monitor.analyze_traffic({
                'event': 'access_denied',
                'resource': resource,
                'user_id': auth_context.user_id,
                **context_data
            })
            
        return decision.allowed
    
    def disconnect(self) -> bool:
        """Disconnect current VPN session.
        
        Returns:
            bool indicating success
        """
        if not self._current_session:
            return True
            
        try:
            auth_context = self._current_session['auth_context']
            
            # Stop the WireGuard interface
            try:
                self.wireguard.stop_interface()
            except Exception as e:
                self.logger.error(f"Failed to stop WireGuard interface: {str(e)}")
                # Continue with cleanup even if interface stop fails
            
            # Clean up any remaining interfaces
            for interface in ['utun6', 'utun7', 'utun8', 'utun9', 'utun10', 'utun11']:
                try:
                    self.wireguard._cleanup_interface(interface)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up interface {interface}: {str(e)}")
            
            # Log disconnection
            self.threat_monitor.analyze_behavior(
                auth_context.user_id,
                {
                    'event': 'disconnection',
                    'timestamp': datetime.now(),
                    'session_duration': (
                        datetime.now() - self._current_session['start_time']
                    ).total_seconds()
                }
            )
            
            # Update connection status
            self._connection_status = ConnectionStatus(
                is_connected=False,
                connected_since=None,
                current_ip=None
            )
            
            self._current_session = None
            return True
            
        except Exception as e:
            # Log error
            if self._current_session and 'auth_context' in self._current_session:
                self.threat_monitor.analyze_traffic({
                    'event': 'disconnection_error',
                    'error': str(e),
                    'user_id': self._current_session['auth_context'].user_id
                })
            return False
    
    def get_connection_status(self) -> ConnectionStatus:
        """Get current connection status.
        
        Returns:
            ConnectionStatus object
        """
        return self.wireguard.get_connection_status() 