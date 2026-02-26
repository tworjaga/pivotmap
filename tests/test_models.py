"""
Unit tests for core data models.
"""

import pytest
from uuid import UUID

from pivotmap.core.models import (
    AttackPath,
    EdgeType,
    ExposureLevel,
    ExploitMaturity,
    GraphEdge,
    GraphNode,
    Host,
    NodeType,
    PrivilegeLevel,
    Service,
    Vulnerability,
)


class TestHost:
    """Test Host model."""

    def test_host_creation(self) -> None:
        """Test basic host creation."""
        host = Host(
            ip="192.168.1.1",
            hostname="test-host",
            os="Linux",
            exposure=ExposureLevel.EXTERNAL,
        )

        assert host.ip == "192.168.1.1"
        assert host.hostname == "test-host"
        assert host.os == "Linux"
        assert host.exposure == ExposureLevel.EXTERNAL
        assert isinstance(host.id, UUID)

    def test_host_defaults(self) -> None:
        """Test host default values."""
        host = Host(ip="10.0.0.1")

        assert host.exposure == ExposureLevel.INTERNAL
        assert host.hostname is None
        assert host.os is None


class TestService:
    """Test Service model."""

    def test_service_creation(self) -> None:
        """Test basic service creation."""
        host_id = UUID("12345678-1234-5678-1234-567812345678")
        service = Service(
            host_id=host_id,
            port=80,
            protocol="tcp",
            name="http",
            version="2.4.41",
        )

        assert service.host_id == host_id
        assert service.port == 80
        assert service.protocol == "tcp"
        assert service.name == "http"
        assert service.version == "2.4.41"

    def test_service_port_validation(self) -> None:
        """Test port number validation."""
        host_id = UUID("12345678-1234-5678-1234-567812345678")

        with pytest.raises(ValueError):
            Service(host_id=host_id, port=0)

        with pytest.raises(ValueError):
            Service(host_id=host_id, port=70000)


    def test_service_protocol_validation(self) -> None:
        """Test protocol validation."""
        host_id = UUID("12345678-1234-5678-1234-567812345678")

        with pytest.raises(ValueError):
            Service(host_id=host_id, port=80, protocol="invalid")


class TestVulnerability:
    """Test Vulnerability model."""

    def test_vulnerability_creation(self) -> None:
        """Test basic vulnerability creation."""
        vuln = Vulnerability(
            cve_id="CVE-2021-44228",
            title="Log4j RCE",
            description="Remote code execution in Log4j",
            cvss_score=10.0,
            exploit_maturity=ExploitMaturity.HIGH,
        )

        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.title == "Log4j RCE"
        assert vuln.cvss_score == 10.0
        assert vuln.exploit_maturity == ExploitMaturity.HIGH

    def test_cve_id_validation(self) -> None:
        """Test CVE ID format validation."""
        with pytest.raises(ValueError):
            Vulnerability(cve_id="INVALID-1234", title="Test")


    def test_cvss_score_validation(self) -> None:
        """Test CVSS score range validation."""
        with pytest.raises(ValueError):
            Vulnerability(title="Test", cvss_score=11.0)

        with pytest.raises(ValueError):
            Vulnerability(title="Test", cvss_score=-1.0)



class TestAttackPath:
    """Test AttackPath model."""

    def test_attack_path_creation(self) -> None:
        """Test basic attack path creation."""
        source = UUID("12345678-1234-5678-1234-567812345678")
        target = UUID("87654321-4321-8765-4321-876543218765")
        path_nodes = [source, UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), target]

        path = AttackPath(
            source_host_id=source,
            target_host_id=target,
            path=path_nodes,
            edges=[(source, path_nodes[1], "exploits"), (path_nodes[1], target, "pivots_to")],
            pivot_score=0.85,
            complexity_score=0.3,
            impact_score=0.9,
            privilege_gain=PrivilegeLevel.ADMIN,
        )


        assert path.source_host_id == source
        assert path.target_host_id == target
        assert len(path.path) == 3
        assert path.pivot_score == 0.85
        assert path.privilege_gain == PrivilegeLevel.ADMIN


class TestGraphNode:
    """Test GraphNode model."""

    def test_graph_node_creation(self) -> None:
        """Test basic graph node creation."""
        entity_id = UUID("12345678-1234-5678-1234-567812345678")
        node = GraphNode(
            node_type=NodeType.HOST,
            entity_id=entity_id,
            label="192.168.1.1",
            weight=1.5,
            criticality=0.8,
        )

        assert node.node_type == NodeType.HOST
        assert node.entity_id == entity_id
        assert node.label == "192.168.1.1"
        assert node.criticality == 0.8


class TestGraphEdge:
    """Test GraphEdge model."""

    def test_graph_edge_creation(self) -> None:
        """Test basic graph edge creation."""
        source = UUID("12345678-1234-5678-1234-567812345678")
        target = UUID("87654321-4321-8765-4321-876543218765")

        edge = GraphEdge(
            source_id=source,
            target_id=target,
            edge_type=EdgeType.EXPLOITS,
            weight=2.0,
            confidence=0.95,
        )

        assert edge.source_id == source
        assert edge.target_id == target
        assert edge.edge_type == EdgeType.EXPLOITS
        assert edge.confidence == 0.95


class TestEnums:
    """Test enumeration values."""

    def test_exposure_levels(self) -> None:
        """Test exposure level values."""
        assert ExposureLevel.INTERNAL.value == "internal"
        assert ExposureLevel.EXTERNAL.value == "external"
        assert ExposureLevel.DMZ.value == "dmz"

    def test_exploit_maturity(self) -> None:
        """Test exploit maturity values."""
        assert ExploitMaturity.UNPROVEN.value == "unproven"
        assert ExploitMaturity.HIGH.value == "high"

    def test_privilege_levels(self) -> None:
        """Test privilege level values."""
        assert PrivilegeLevel.NONE.value == "none"
        assert PrivilegeLevel.SYSTEM.value == "system"

    def test_node_types(self) -> None:
        """Test node type values."""
        assert NodeType.HOST.value == "host"
        assert NodeType.VULNERABILITY.value == "vulnerability"

    def test_edge_types(self) -> None:
        """Test edge type values."""
        assert EdgeType.EXPOSES.value == "exposes"
        assert EdgeType.PIVOTS_TO.value == "pivots_to"
