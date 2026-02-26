"""
Core data models for PivotMap.

Defines the fundamental entities: Host, Service, Vulnerability,
and their relationships for attack path analysis.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class ExposureLevel(str, Enum):
    """Network exposure classification."""
    INTERNAL = "internal"
    DMZ = "dmz"
    EXTERNAL = "external"
    RESTRICTED = "restricted"


class ExploitMaturity(str, Enum):
    """Exploit availability and maturity."""
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"
    NOT_DEFINED = "not_defined"


class PrivilegeLevel(str, Enum):
    """Privilege levels in compromise chain."""
    NONE = "none"
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


class NodeType(str, Enum):
    """Graph node classification."""
    HOST = "host"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    PRIVILEGE = "privilege"
    SEGMENT = "segment"


class EdgeType(str, Enum):
    """Graph edge classification."""
    EXPOSES = "exposes"
    VULNERABLE_TO = "vulnerable_to"
    EXPLOITS = "exploits"
    ESCALATES_TO = "escalates_to"
    PIVOTS_TO = "pivots_to"


class Host(BaseModel):
    """Network host entity."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    ip: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="DNS hostname")
    mac: Optional[str] = Field(None, description="MAC address")
    os: Optional[str] = Field(None, description="Operating system")
    exposure: ExposureLevel = Field(default=ExposureLevel.INTERNAL)
    network_segment: Optional[str] = Field(None)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Service(BaseModel):
    """Network service entity."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    host_id: UUID = Field(..., description="Parent host reference")
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", pattern="^(tcp|udp)$")
    name: Optional[str] = Field(None, description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    banner: Optional[str] = Field(None, description="Service banner")
    state: str = Field(default="open", pattern="^(open|closed|filtered)$")
    metadata: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    """Vulnerability record."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    cve_id: Optional[str] = Field(
        None,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="CVE identifier"
    )
    service_id: Optional[UUID] = Field(None, description="Affected service")
    host_id: Optional[UUID] = Field(None, description="Affected host")
    title: str = Field(..., description="Vulnerability title")
    description: Optional[str] = Field(None)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(None)
    exploit_maturity: ExploitMaturity = Field(default=ExploitMaturity.NOT_DEFINED)
    cwe_id: Optional[str] = Field(None, pattern=r"^CWE-\d+$")
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """Computed attack path."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    source_host_id: UUID = Field(..., description="Entry point host")
    target_host_id: UUID = Field(..., description="Compromise target")
    path: list[UUID] = Field(..., description="Ordered node sequence")
    edges: list[tuple[UUID, UUID, str]] = Field(
        ...,
        description="Edge tuples (source, target, type)"
    )
    pivot_score: float = Field(..., ge=0.0, le=1.0)
    complexity_score: float = Field(..., ge=0.0, le=1.0)
    impact_score: float = Field(..., ge=0.0, le=1.0)
    privilege_gain: PrivilegeLevel = Field(default=PrivilegeLevel.NONE)
    exploit_chain: list[Vulnerability] = Field(default_factory=list)
    estimated_time: Optional[int] = Field(None, description="Estimated minutes to compromise")


class GraphNode(BaseModel):
    """Graph node representation."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    node_type: NodeType
    entity_id: UUID = Field(..., description="Reference to Host/Service/Vulnerability")
    label: str = Field(...)
    weight: float = Field(default=1.0, ge=0.0)
    criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Graph edge representation."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    source_id: UUID = Field(...)
    target_id: UUID = Field(...)
    edge_type: EdgeType
    weight: float = Field(default=1.0, ge=0.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanImport(BaseModel):
    """Raw scan import metadata."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    source_type: str = Field(..., description="nmap, nuclei, etc.")
    source_file: Optional[str] = Field(None)
    imported_at: datetime = Field(default_factory=datetime.utcnow)
    host_count: int = Field(default=0)
    service_count: int = Field(default=0)
    vulnerability_count: int = Field(default=0)
    raw_data: Optional[dict[str, Any]] = Field(None)
