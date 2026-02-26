"""
Graph construction and management using networkx.

Builds directed attack graphs with weighted edges for path analysis.
"""

from typing import Any, Optional
from uuid import UUID

import networkx as nx

from pivotmap.core.models import (
    AttackPath,
    EdgeType,
    GraphEdge,
    GraphNode,
    Host,
    NodeType,
    PrivilegeLevel,
    Service,
    Vulnerability,
)


class AttackGraph:
    """
    Directed graph for attack path modeling.

    Nodes: Host, Service, Vulnerability, Privilege, Segment
    Edges: exposes, vulnerable_to, exploits, escalates_to, pivots_to
    """

    def __init__(self) -> None:
        """Initialize empty directed graph."""
        self.graph: nx.DiGraph = nx.DiGraph()
        self._node_map: dict[UUID, str] = {}
        self._entity_map: dict[UUID, Any] = {}

    def _get_node_id(self, entity_id: UUID, node_type: NodeType) -> str:
        """Generate unique node identifier."""
        return f"{node_type.value}:{str(entity_id)}"

    def add_host(self, host: Host, weight: float = 1.0) -> str:
        """
        Add host node to graph.

        Returns node identifier.
        """
        node_id: str = self._get_node_id(host.id, NodeType.HOST)

        self.graph.add_node(
            node_id,
            node_type=NodeType.HOST.value,
            entity_id=str(host.id),
            label=host.hostname or host.ip,
            ip=host.ip,
            hostname=host.hostname,
            os=host.os,
            exposure=host.exposure.value,
            weight=weight,
            criticality=0.0,
        )

        self._node_map[host.id] = node_id
        self._entity_map[host.id] = host

        return node_id

    def add_service(
        self,
        service: Service,
        host: Host,
        weight: float = 1.0,
        criticality: float = 0.5
    ) -> str:
        """
        Add service node and connect to host.

        Returns node identifier.
        """
        node_id: str = self._get_node_id(service.id, NodeType.SERVICE)

        self.graph.add_node(
            node_id,
            node_type=NodeType.SERVICE.value,
            entity_id=str(service.id),
            label=f"{service.name or 'unknown'}/{service.port}",
            port=service.port,
            protocol=service.protocol,
            version=service.version,
            state=service.state,
            weight=weight,
            criticality=criticality,
        )

        self._node_map[service.id] = node_id
        self._entity_map[service.id] = service

        host_node: Optional[str] = self._node_map.get(host.id)
        if host_node:
            self.graph.add_edge(
                host_node,
                node_id,
                edge_type=EdgeType.EXPOSES.value,
                weight=1.0,
                confidence=1.0,
            )

        return node_id

    def add_vulnerability(
        self,
        vulnerability: Vulnerability,
        service: Optional[Service] = None,
        host: Optional[Host] = None,
        weight: float = 1.0,
        criticality: float = 0.5
    ) -> str:
        """
        Add vulnerability node and connect to affected entity.

        Returns node identifier.
        """
        node_id: str = self._get_node_id(vulnerability.id, NodeType.VULNERABILITY)

        label: str = vulnerability.cve_id or vulnerability.title[:30]

        self.graph.add_node(
            node_id,
            node_type=NodeType.VULNERABILITY.value,
            entity_id=str(vulnerability.id),
            label=label,
            cve_id=vulnerability.cve_id,
            cvss_score=vulnerability.cvss_score,
            exploit_maturity=vulnerability.exploit_maturity.value,
            weight=weight,
            criticality=criticality,
        )

        self._node_map[vulnerability.id] = node_id
        self._entity_map[vulnerability.id] = vulnerability

        target_node: Optional[str] = None

        if service and service.id in self._node_map:
            target_node = self._node_map[service.id]
        elif host and host.id in self._node_map:
            target_node = self._node_map[host.id]

        if target_node:
            self.graph.add_edge(
                target_node,
                node_id,
                edge_type=EdgeType.VULNERABLE_TO.value,
                weight=weight,
                confidence=0.9,
            )

        return node_id

    def add_privilege_node(
        self,
        host_id: UUID,
        level: PrivilegeLevel,
        weight: float = 1.0
    ) -> str:
        """
        Add privilege level node for a host.

        Returns node identifier.
        """
        pseudo_id: UUID = UUID(f"{host_id}-{level.value}")
        node_id: str = self._get_node_id(pseudo_id, NodeType.PRIVILEGE)

        self.graph.add_node(
            node_id,
            node_type=NodeType.PRIVILEGE.value,
            entity_id=str(pseudo_id),
            label=f"{level.value}@{host_id}",
            privilege_level=level.value,
            host_id=str(host_id),
            weight=weight,
            criticality=1.0 if level == PrivilegeLevel.SYSTEM else 0.7,
        )

        host_node: Optional[str] = self._node_map.get(host_id)
        if host_node:
            self.graph.add_edge(
                host_node,
                node_id,
                edge_type=EdgeType.ESCALATES_TO.value,
                weight=weight,
                confidence=0.8,
            )

        return node_id

    def add_pivot_edge(
        self,
        source_host_id: UUID,
        target_host_id: UUID,
        weight: float = 1.0,
        confidence: float = 0.7
    ) -> None:
        """
        Add lateral movement edge between hosts.
        """
        source_node: Optional[str] = self._node_map.get(source_host_id)
        target_node: Optional[str] = self._node_map.get(target_host_id)

        if source_node and target_node:
            self.graph.add_edge(
                source_node,
                target_node,
                edge_type=EdgeType.PIVOTS_TO.value,
                weight=weight,
                confidence=confidence,
            )

    def get_node(self, entity_id: UUID) -> Optional[dict[str, Any]]:
        """Retrieve node data by entity ID."""
        node_id: Optional[str] = self._node_map.get(entity_id)
        if node_id:
            return dict(self.graph.nodes[node_id])
        return None

    def get_neighbors(
        self,
        entity_id: UUID,
        edge_type: Optional[EdgeType] = None
    ) -> list[dict[str, Any]]:
        """Get neighboring nodes with optional edge type filter."""
        node_id: Optional[str] = self._node_map.get(entity_id)
        if not node_id:
            return []

        neighbors: list[dict[str, Any]] = []

        for neighbor_id in self.graph.successors(node_id):
            edge_data: dict[str, Any] = self.graph.edges[node_id, neighbor_id]

            if edge_type and edge_data.get("edge_type") != edge_type.value:
                continue

            node_data: dict[str, Any] = dict(self.graph.nodes[neighbor_id])
            node_data["_edge"] = edge_data
            neighbors.append(node_data)

        return neighbors

    def find_shortest_path(
        self,
        source_id: UUID,
        target_id: UUID,
        weight: str = "weight"
    ) -> Optional[list[UUID]]:
        """
        Find shortest path using Dijkstra algorithm.

        Returns ordered list of entity IDs.
        """
        source_node: Optional[str] = self._node_map.get(source_id)
        target_node: Optional[str] = self._node_map.get(target_id)

        if not source_node or not target_node:
            return None

        try:
            path: list[str] = nx.shortest_path(
                self.graph,
                source_node,
                target_node,
                weight=weight
            )

            result: list[UUID] = []
            for node_id in path:
                node_data: dict[str, Any] = self.graph.nodes[node_id]
                entity_id_str: str = node_data.get("entity_id")
                if entity_id_str:
                    result.append(UUID(entity_id_str))

            return result

        except nx.NetworkXNoPath:
            return None

    def find_all_paths(
        self,
        source_id: UUID,
        target_id: UUID,
        cutoff: int = 10
    ) -> list[list[UUID]]:
        """
        Find all simple paths up to length cutoff.
        """
        source_node: Optional[str] = self._node_map.get(source_id)
        target_node: Optional[str] = self._node_map.get(target_id)

        if not source_node or not target_node:
            return []

        try:
            paths: list[list[str]] = list(nx.all_simple_paths(
                self.graph,
                source_node,
                target_node,
                cutoff=cutoff
            ))

            result: list[list[UUID]] = []
            for path in paths:
                entity_path: list[UUID] = []
                for node_id in path:
                    node_data: dict[str, Any] = self.graph.nodes[node_id]
                    entity_id_str: str = node_data.get("entity_id")
                    if entity_id_str:
                        entity_path.append(UUID(entity_id_str))
                result.append(entity_path)

            return result

        except nx.NetworkXNoPath:
            return []

    def get_critical_nodes(self, top_n: int = 10) -> list[tuple[UUID, float]]:
        """
        Identify most critical nodes by centrality metrics.

        Returns list of (entity_id, centrality_score) tuples.
        """
        if len(self.graph) == 0:
            return []

        betweenness: dict[str, float] = nx.betweenness_centrality(
            self.graph,
            weight="weight"
        )

        scored: list[tuple[str, float]] = sorted(
            betweenness.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]

        result: list[tuple[UUID, float]] = []
        for node_id, score in scored:
            node_data: dict[str, Any] = self.graph.nodes[node_id]
            entity_id_str: str = node_data.get("entity_id")
            if entity_id_str:
                result.append((UUID(entity_id_str), round(score, 4)))

        return result

    def prune_low_criticality(self, threshold: float = 0.1) -> int:
        """
        Remove nodes with criticality below threshold.

        Returns count of removed nodes.
        """
        to_remove: list[str] = []

        for node_id, data in self.graph.nodes(data=True):
            criticality: float = data.get("criticality", 0.0)
            if criticality < threshold:
                to_remove.append(node_id)

        self.graph.remove_nodes_from(to_remove)

        for node_id in to_remove:
            for entity_id, mapped_id in list(self._node_map.items()):
                if mapped_id == node_id:
                    del self._node_map[entity_id]
                    if entity_id in self._entity_map:
                        del self._entity_map[entity_id]
                    break

        return len(to_remove)

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary format."""
        nodes: list[dict[str, Any]] = []
        for node_id, data in self.graph.nodes(data=True):
            node_copy: dict[str, Any] = dict(data)
            node_copy["id"] = node_id
            nodes.append(node_copy)

        edges: list[dict[str, Any]] = []
        for source, target, data in self.graph.edges(data=True):
            edge_copy: dict[str, Any] = dict(data)
            edge_copy["source"] = source
            edge_copy["target"] = target
            edges.append(edge_copy)

        return {
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def get_statistics(self) -> dict[str, Any]:
        """Return graph statistics."""
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "host_nodes": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == NodeType.HOST.value
            ),
            "service_nodes": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == NodeType.SERVICE.value
            ),
            "vulnerability_nodes": sum(
                1 for _, d in self.graph.nodes(data=True)
                if d.get("node_type") == NodeType.VULNERABILITY.value
            ),
            "density": round(nx.density(self.graph), 4),
            "is_connected": nx.is_weakly_connected(self.graph),
        }
