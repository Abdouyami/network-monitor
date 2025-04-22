# core/models.py
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
import json

@dataclass
class PortInfo:
    """Information about an open port on a device"""
    port: int
    protocol: str
    service: str
    version: str = ""
    cpe: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class Device:
    """A device discovered on the network"""
    ip_address: str
    status: str
    hostname: Optional[str]
    mac_address: Optional[str]
    vendor: Optional[str]
    os: Optional[str]
    ports: List[PortInfo]
    device_type: str
    confidence: str
    is_new: bool
    is_authorized: bool
    whitelisted: bool
    last_seen: str
    is_scanner: bool
    first_seen: Optional[str] = None
    p0f_data: Optional[str] = None
    dhcp_fingerprint: Optional[Dict] = None
    fingerprint_method: Optional[str] = None
    vulnerability_score: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert port objects to dictionaries
        data['ports'] = [port.to_dict() for port in self.ports]
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class ScanResult:
    """Results of a network scan"""
    scan_time: str
    platform: str
    devices: List[Dict[str, Any]]
    stats: Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create from dictionary"""
        return cls(
            scan_time=data.get('scan_time', ''),
            platform=data.get('platform', ''),
            devices=data.get('devices', []),
            stats=data.get('stats', {})
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class ThreatAlert:
    """Represents a detected threat or security issue"""
    alert_type: str
    details: Dict[str, Any]
    timestamp: str
    severity: str = "medium"
    resolved: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create from dictionary"""
        return cls(
            alert_type=data.get('alert_type', ''),
            details=data.get('details', {}),
            timestamp=data.get('timestamp', ''),
            severity=data.get('severity', 'medium'),
            resolved=data.get('resolved', False)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class VulnerabilityReport:
    """Detailed vulnerability analysis report for a device"""
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    timestamp: str
    risk_level: str  # high, medium, low
    risk_score: int
    high_risk_issues: List[str]
    medium_risk_issues: List[str]
    low_risk_issues: List[str]
    open_ports: Dict[str, List[int]]
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)