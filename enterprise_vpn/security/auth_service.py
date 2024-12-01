"""Authentication service implementation."""

from abc import ABC, abstractmethod
from typing import Optional
import logging

class Authenticator(ABC):
    """Base class for authentication providers."""
    
    @abstractmethod
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user with username and password."""
        pass
    
    @abstractmethod
    def validate_session(self, session_id: str) -> bool:
        """Validate an existing session."""
        pass

class DemoAuthenticator(Authenticator):
    """Demo authenticator for testing."""
    
    def __init__(self):
        """Initialize demo authenticator."""
        self.logger = logging.getLogger('auth.demo')
        self._demo_accounts = {
            'developer@company.com': 'demo123',
            'admin@company.com': 'admin123',
            'user@company.com': 'user123'
        }
    
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate using demo credentials."""
        self.logger.info(f"Demo authentication attempt for user: {username}")
        return self._demo_accounts.get(username) == password
    
    def validate_session(self, session_id: str) -> bool:
        """Always return True for demo sessions."""
        return True

class AuthenticationService:
    """Main authentication service."""
    
    def __init__(self, authenticator: Authenticator):
        """Initialize authentication service.
        
        Args:
            authenticator: Authentication provider implementation
        """
        self.logger = logging.getLogger('auth.service')
        self.authenticator = authenticator
        
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user.
        
        Args:
            username: User's email or username
            password: User's password
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        try:
            self.logger.info(f"Authentication attempt for user: {username}")
            return self.authenticator.authenticate(username, password)
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return False
    
    def validate_session(self, session_id: str) -> bool:
        """Validate an existing session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            bool: True if session is valid, False otherwise
        """
        try:
            return self.authenticator.validate_session(session_id)
        except Exception as e:
            self.logger.error(f"Session validation error: {str(e)}")
            return False 