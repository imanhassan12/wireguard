"""Access control module for granular network access management."""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class AccessLevel(Enum):
    """Access level definitions."""
    NONE = 0
    READ = 1
    WRITE = 2
    ADMIN = 3

@dataclass
class AccessPolicy:
    """Represents an access policy."""
    policy_id: str
    name: str
    description: str
    resources: List[str]  # List of resource identifiers
    allowed_ips: List[str]
    allowed_ports: List[int]
    required_access_level: AccessLevel
    time_restrictions: Optional[Dict[str, Any]] = None
    location_restrictions: Optional[List[str]] = None

@dataclass
class AccessDecision:
    """Result of access control decision."""
    allowed: bool
    policy_id: Optional[str]
    reason: str
    timestamp: datetime
    expires_at: Optional[datetime] = None

class AccessController:
    """Manages granular access control."""
    
    def __init__(self):
        """Initialize access controller."""
        self._policies: Dict[str, AccessPolicy] = {}
        self._user_policies: Dict[str, Set[str]] = {}  # user_id -> policy_ids
        self._decisions_cache: Dict[str, AccessDecision] = {}
    
    def add_policy(self, policy: AccessPolicy):
        """Add or update an access policy.
        
        Args:
            policy: AccessPolicy object
        """
        self._policies[policy.policy_id] = policy
    
    def assign_policy_to_user(self, user_id: str, policy_id: str):
        """Assign a policy to a user.
        
        Args:
            user_id: User identifier
            policy_id: Policy identifier
        """
        if user_id not in self._user_policies:
            self._user_policies[user_id] = set()
        self._user_policies[user_id].add(policy_id)
    
    def check_access(self, user_id: str, resource: str, 
                    context: Dict[str, Any]) -> AccessDecision:
        """Check if access should be granted.
        
        Args:
            user_id: User identifier
            resource: Resource identifier
            context: Access context information
            
        Returns:
            AccessDecision object
        """
        if user_id not in self._user_policies:
            return AccessDecision(
                allowed=False,
                policy_id=None,
                reason="No policies assigned to user",
                timestamp=datetime.now()
            )
        
        # Check each policy assigned to the user
        for policy_id in self._user_policies[user_id]:
            policy = self._policies.get(policy_id)
            if not policy:
                continue
                
            if self._policy_allows_access(policy, resource, context):
                return AccessDecision(
                    allowed=True,
                    policy_id=policy_id,
                    reason="Access granted by policy",
                    timestamp=datetime.now()
                )
        
        return AccessDecision(
            allowed=False,
            policy_id=None,
            reason="No matching policy allows access",
            timestamp=datetime.now()
        )
    
    def _policy_allows_access(self, policy: AccessPolicy, 
                            resource: str, context: Dict[str, Any]) -> bool:
        """Check if a policy allows access under given context.
        
        Args:
            policy: AccessPolicy to check
            resource: Resource identifier
            context: Access context information
            
        Returns:
            bool indicating if access is allowed
        """
        if resource not in policy.resources:
            return False
            
        # Check IP restrictions
        if policy.allowed_ips and \
           context.get('source_ip') not in policy.allowed_ips:
            return False
            
        # Check port restrictions
        if policy.allowed_ports and \
           context.get('port') not in policy.allowed_ports:
            return False
            
        # Check time restrictions
        if policy.time_restrictions and \
           not self._check_time_restrictions(policy.time_restrictions):
            return False
            
        # Check location restrictions
        if policy.location_restrictions and \
           context.get('location') not in policy.location_restrictions:
            return False
            
        return True
    
    def _check_time_restrictions(self, restrictions: Dict[str, Any]) -> bool:
        """Check if current time meets restrictions.
        
        Args:
            restrictions: Time restriction configuration
            
        Returns:
            bool indicating if time restrictions are met
        """
        # TODO: Implement time restriction checking
        return True 