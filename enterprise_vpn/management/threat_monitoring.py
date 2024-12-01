"""Threat monitoring and analysis module."""

import logging
import psutil
import os
import platform
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

@dataclass
class SystemMetrics:
    """System metrics data."""
    cpu_usage: float
    memory_usage: float
    network_throughput: float
    active_connections: int
    timestamp: datetime
    error_message: Optional[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatEvent:
    """Represents a detected threat event."""
    event_id: str
    timestamp: datetime
    threat_type: str
    threat_level: ThreatLevel
    source_ip: Optional[str]
    target_ip: Optional[str]
    user_id: Optional[str]
    description: str
    raw_data: Dict[str, Any]

@dataclass
class BehaviorAnalysis:
    """User behavior analysis results."""
    user_id: str
    timestamp: datetime
    unusual_patterns: List[str]
    risk_score: float
    recommendation: str

class ThreatMonitor:
    """Real-time threat monitoring and analysis."""
    
    def __init__(self):
        """Initialize threat monitor."""
        self.logger = logging.getLogger('vpn_monitor')
        self._threat_history: List[ThreatEvent] = []
        self._behavior_history: Dict[str, List[BehaviorAnalysis]] = {}
        self._last_metrics: Optional[SystemMetrics] = None
        self._network_baseline = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'last_update': datetime.now()
        }
        
        # Check initial permissions
        self._check_permissions()
    
    def _check_permissions(self) -> Dict[str, bool]:
        """Check what permissions we have for monitoring.
        
        Returns:
            Dict of permission states
        """
        permissions = {
            'can_read_cpu': True,
            'can_read_memory': True,
            'can_read_network': True,
            'can_read_connections': True
        }
        
        try:
            psutil.cpu_percent(interval=None)
        except (psutil.AccessDenied, TimeoutError):
            permissions['can_read_cpu'] = False
            self.logger.warning("No permission to read CPU metrics")
        
        try:
            psutil.virtual_memory()
        except (psutil.AccessDenied, TimeoutError):
            permissions['can_read_memory'] = False
            self.logger.warning("No permission to read memory metrics")
        
        try:
            psutil.net_io_counters()
        except (psutil.AccessDenied, TimeoutError):
            permissions['can_read_network'] = False
            self.logger.warning("No permission to read network metrics")
        
        try:
            psutil.net_connections()
        except (psutil.AccessDenied, TimeoutError):
            permissions['can_read_connections'] = False
            self.logger.warning("No permission to read connection information")
        
        # Log system information
        self.logger.info(f"Running on {platform.system()} {platform.release()}")
        self.logger.info(f"Monitoring permissions: {permissions}")
        
        if platform.system() == "Darwin":  # macOS
            self.logger.info("On macOS, some metrics may require sudo privileges")
        
        return permissions
    
    def collect_metrics(self) -> SystemMetrics:
        """Collect current system metrics.
        
        Returns:
            SystemMetrics object with current system state
        """
        warnings = []
        metrics_data = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'network_throughput': 0.0,
            'active_connections': 0
        }
        
        try:
            # Collect CPU usage (non-blocking)
            try:
                metrics_data['cpu_usage'] = psutil.cpu_percent(interval=None)
            except (psutil.AccessDenied, TimeoutError):
                warnings.append("CPU metrics collection requires elevated privileges")
            
            # Collect memory usage
            try:
                memory = psutil.virtual_memory()
                metrics_data['memory_usage'] = memory.percent
            except (psutil.AccessDenied, TimeoutError):
                warnings.append("Memory metrics collection requires elevated privileges")
            
            # Collect network throughput
            try:
                net_io = psutil.net_io_counters()
                current_time = datetime.now()
                time_diff = (current_time - self._network_baseline['last_update']).total_seconds()
                
                if time_diff > 0:
                    bytes_sent_diff = net_io.bytes_sent - self._network_baseline['bytes_sent']
                    bytes_recv_diff = net_io.bytes_recv - self._network_baseline['bytes_recv']
                    metrics_data['network_throughput'] = (bytes_sent_diff + bytes_recv_diff) / time_diff
                
                # Update baseline
                self._network_baseline = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'last_update': current_time
                }
            except (psutil.AccessDenied, TimeoutError):
                warnings.append("Network metrics collection requires elevated privileges")
            
            # Count active connections (only count established connections)
            try:
                metrics_data['active_connections'] = len([
                    conn for conn in psutil.net_connections(kind='inet')
                    if conn.status == 'ESTABLISHED'
                ])
            except (psutil.AccessDenied, TimeoutError, psutil.Error):
                warnings.append("Connection metrics collection requires elevated privileges")
            
            metrics = SystemMetrics(
                cpu_usage=metrics_data['cpu_usage'],
                memory_usage=metrics_data['memory_usage'],
                network_throughput=float(metrics_data['network_throughput']),
                active_connections=metrics_data['active_connections'],
                timestamp=datetime.now(),
                warnings=warnings
            )
            
            # Only log warnings once per unique message
            for warning in warnings:
                if not hasattr(self, '_logged_warnings'):
                    self._logged_warnings = set()
                if warning not in self._logged_warnings:
                    self.logger.warning(warning)
                    self._logged_warnings.add(warning)
            
            self._last_metrics = metrics
            return metrics
            
        except Exception as e:
            error_msg = f"Error collecting metrics: {str(e)}"
            self.logger.error(error_msg)
            return SystemMetrics(
                cpu_usage=0.0,
                memory_usage=0.0,
                network_throughput=0.0,
                active_connections=0,
                timestamp=datetime.now(),
                error_message=error_msg,
                warnings=warnings
            )
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status and capabilities.
        
        Returns:
            Dict containing monitoring status information
        """
        permissions = self._check_permissions()
        metrics = self._last_metrics or self.collect_metrics()
        
        return {
            'system': {
                'os': platform.system(),
                'release': platform.release(),
                'machine': platform.machine()
            },
            'permissions': permissions,
            'active_metrics': {
                'cpu_available': permissions['can_read_cpu'],
                'memory_available': permissions['can_read_memory'],
                'network_available': permissions['can_read_network'],
                'connections_available': permissions['can_read_connections']
            },
            'current_metrics': {
                'cpu_usage': metrics.cpu_usage if permissions['can_read_cpu'] else None,
                'memory_usage': metrics.memory_usage if permissions['can_read_memory'] else None,
                'network_throughput': metrics.network_throughput if permissions['can_read_network'] else None,
                'active_connections': metrics.active_connections if permissions['can_read_connections'] else None,
            },
            'warnings': metrics.warnings
        }
    
    def get_process_info(self) -> Dict[str, Any]:
        """Get information about the current process.
        
        Returns:
            Dict containing process information
        """
        try:
            process = psutil.Process(os.getpid())
            return {
                'pid': process.pid,
                'username': process.username(),
                'memory_percent': process.memory_percent(),
                'cpu_percent': process.cpu_percent(interval=0.1),
                'status': process.status(),
                'create_time': datetime.fromtimestamp(process.create_time())
            }
        except (psutil.AccessDenied, TimeoutError, psutil.Error) as e:
            self.logger.warning(f"Unable to collect process info: {str(e)}")
            return {
                'pid': os.getpid(),
                'error': str(e)
            }
    
    def analyze_traffic(self, traffic_data: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Analyze network traffic for threats.
        
        Args:
            traffic_data: Network traffic data
            
        Returns:
            ThreatEvent if threat detected, None otherwise
        """
        try:
            # Get current metrics for context
            metrics = self._last_metrics or self.collect_metrics()
            
            # Basic traffic analysis (placeholder implementation)
            is_suspicious = False
            
            # Check for high network usage
            if metrics.network_throughput > 1000000:  # More than 1 MB/s
                is_suspicious = True
            
            # Check for unusual connection count
            if metrics.active_connections > 100:  # More than 100 active connections
                is_suspicious = True
            
            if is_suspicious:
                threat = ThreatEvent(
                    event_id=f"threat_{datetime.now().timestamp()}",
                    timestamp=datetime.now(),
                    threat_type="suspicious_traffic",
                    threat_level=ThreatLevel.MEDIUM,
                    source_ip=traffic_data.get('source_ip'),
                    target_ip=traffic_data.get('target_ip'),
                    user_id=traffic_data.get('user_id'),
                    description="Suspicious traffic pattern detected",
                    raw_data={**traffic_data, 'metrics': metrics}
                )
                self._threat_history.append(threat)
                return threat
                
        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {str(e)}")
            
        return None
    
    def analyze_behavior(self, user_id: str, 
                        activity_data: Dict[str, Any]) -> BehaviorAnalysis:
        """Analyze user behavior for anomalies.
        
        Args:
            user_id: User identifier
            activity_data: User activity data
            
        Returns:
            BehaviorAnalysis object
        """
        try:
            # Get current metrics for context
            metrics = self._last_metrics or self.collect_metrics()
            
            # Get user's behavior history
            user_history = self._behavior_history.get(user_id, [])
            
            # Calculate risk score based on various factors
            risk_score = 0.0
            unusual_patterns = []
            
            # Check for high resource usage
            if metrics.cpu_usage > 90:
                risk_score += 0.3
                unusual_patterns.append("High CPU usage")
            
            if metrics.memory_usage > 90:
                risk_score += 0.3
                unusual_patterns.append("High memory usage")
            
            # Check connection patterns
            if metrics.active_connections > 50:
                risk_score += 0.2
                unusual_patterns.append("Unusual number of connections")
            
            # Generate recommendation
            if risk_score > 0.7:
                recommendation = "Investigate high resource usage and connection patterns"
            elif risk_score > 0.3:
                recommendation = "Monitor resource usage"
            else:
                recommendation = "No action needed"
            
            # Create analysis result
            analysis = BehaviorAnalysis(
                user_id=user_id,
                timestamp=datetime.now(),
                unusual_patterns=unusual_patterns,
                risk_score=risk_score,
                recommendation=recommendation
            )
            
            # Update history
            if user_id not in self._behavior_history:
                self._behavior_history[user_id] = []
            self._behavior_history[user_id].append(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavior: {str(e)}")
            return BehaviorAnalysis(
                user_id=user_id,
                timestamp=datetime.now(),
                unusual_patterns=["Error during analysis"],
                risk_score=0.0,
                recommendation="Analysis failed, manual review recommended"
            )
    
    def get_threat_history(self, 
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          min_level: ThreatLevel = ThreatLevel.INFO) -> List[ThreatEvent]:
        """Get historical threat events.
        
        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter
            min_level: Minimum threat level to include
            
        Returns:
            List of ThreatEvent objects
        """
        try:
            filtered_threats = [
                t for t in self._threat_history
                if t.threat_level.value >= min_level.value
            ]
            
            if start_time:
                filtered_threats = [t for t in filtered_threats if t.timestamp >= start_time]
            if end_time:
                filtered_threats = [t for t in filtered_threats if t.timestamp <= end_time]
                
            return filtered_threats
            
        except Exception as e:
            self.logger.error(f"Error retrieving threat history: {str(e)}")
            return []
    
    def _is_suspicious_traffic(self, traffic_data: Dict[str, Any]) -> bool:
        """Analyze if traffic is suspicious.
        
        Args:
            traffic_data: Network traffic data
            
        Returns:
            bool indicating if traffic is suspicious
        """
        try:
            # Get current metrics
            metrics = self._last_metrics or self.collect_metrics()
            
            # Check for suspicious patterns
            if metrics.network_throughput > 1000000:  # More than 1 MB/s
                return True
                
            if metrics.active_connections > 100:  # More than 100 connections
                return True
                
            # Add more sophisticated checks here
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking suspicious traffic: {str(e)}")
            return False
    
    def log_event(self, event_type: str, details: Dict[str, Any]):
        """Log a system event.
        
        Args:
            event_type: Type of event
            details: Event details
        """
        try:
            # Add current metrics to event details
            if self._last_metrics:
                details['metrics'] = {
                    'cpu_usage': self._last_metrics.cpu_usage,
                    'memory_usage': self._last_metrics.memory_usage,
                    'network_throughput': self._last_metrics.network_throughput,
                    'active_connections': self._last_metrics.active_connections
                }
            
            self.logger.info(f"Event: {event_type}", extra=details)
            
        except Exception as e:
            self.logger.error(f"Error logging event: {str(e)}")