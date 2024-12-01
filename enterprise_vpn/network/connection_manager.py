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
    
    def establish_connection(self, auth_context: AuthenticationContext) -> bool:
        """Establish a VPN connection with detailed error handling."""
        if not auth_context.authenticated:
            raise VPNConnectionError("Authentication required", {
                'error_type': 'authentication',
                'user_id': auth_context.user_id
            })
        
        try:
            # Step 1: Check server availability
            server_available, server_error = self.check_server_availability()
            if not server_available:
                server_info = self.wireguard.get_server_info()
                raise VPNConnectionError("Server connectivity check failed", {
                    'error_type': 'server_connectivity',
                    'details': server_error,
                    'server': server_info['endpoint']
                })
            
            # Step 2: Validate network configuration
            config_valid, config_error = self.validate_network_config()
            if not config_valid:
                raise VPNConnectionError("Network configuration validation failed", {
                    'error_type': 'network_config',
                    'details': config_error
                })
            
            # Step 3: Security validation
            try:
                if not self.validator.enforce_policies(
                    auth_context.user_id,
                    auth_context.device_id,
                    auth_context.context_data or {}
                ):
                    raise VPNConnectionError("Security policy validation failed", {
                        'error_type': 'security_policy',
                        'user_id': auth_context.user_id,
                        'device_id': auth_context.device_id
                    })
            except Exception as e:
                raise VPNConnectionError("Security validation error", {
                    'error_type': 'security_validation',
                    'details': str(e)
                })
            
            # Step 4: Create peer configuration
            try:
                peer_config = self.wireguard.create_peer(
                    name=auth_context.user_id,
                    allowed_ips="0.0.0.0/0"
                )
            except WireGuardError as e:
                raise VPNConnectionError("Peer configuration failed", {
                    'error_type': 'peer_config',
                    'details': str(e)
                })
            
            # Step 5: Apply configuration
            try:
                if not self.wireguard.apply_config(peer_config['config']):
                    raise VPNConnectionError("Configuration application failed", {
                        'error_type': 'config_application'
                    })
            except WireGuardError as e:
                raise VPNConnectionError("Configuration error", {
                    'error_type': 'config_error',
                    'details': str(e)
                })
            
            # Step 6: Initialize session
            self._current_session = {
                'auth_context': auth_context,
                'start_time': datetime.now(),
                'peer_config': peer_config
            }
            
            # Step 7: Start monitoring
            try:
                self.threat_monitor.analyze_behavior(
                    auth_context.user_id,
                    {
                        'event': 'connection_established',
                        'timestamp': datetime.now()
                    }
                )
            except Exception as e:
                self.logger.warning(f"Monitoring initialization warning: {str(e)}")
            
            return True
            
        except VPNConnectionError:
            raise
        except Exception as e:
            raise VPNConnectionError("Unexpected error during connection", {
                'error_type': 'unexpected',
                'details': str(e)
            })
    
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