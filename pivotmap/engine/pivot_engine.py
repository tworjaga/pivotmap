"""
Pivot engine for attack path computation.

Computes shortest paths, highest impact paths, and privilege escalation chains.
"""

from typing import Any, Optional
from uuid import UUID

import networkx as nx

from pivotmap.core.models import AttackPath, Host, PrivilegeLevel, Service, Vulnerability
from pivotmap.core.graph_builder import AttackGraph
from pivotmap.core.scorer import PivotScorer


class PivotEngine:
    """
    Compute attack paths and pivot opportunities.

    Implements Dijkstra shortest path and custom ranking algorithms.
    """

    def __init__(self, graph: AttackGraph, scorer: Optional[PivotScorer] = None) -> None:
        """
        Initialize pivot engine.

        Args:
            graph: Attack graph with hosts, services, vulnerabilities
            scorer: PivotScorer instance for path ranking
        """
        self.graph: AttackGraph = graph
        self.scorer: PivotScorer = scorer or PivotScorer()

    def find_shortest_compromise_path(
        self,
        entry_host_id: UUID,
        target_host_id: UUID
    ) -> Optional[AttackPath]:
        """
        Find shortest path from entry to target.

        Uses Dijkstra algorithm with vulnerability weights.

        Args:
            entry_host_id: Starting host (entry point)
            target_host_id: Target host to compromise

        Returns:
            AttackPath or None if no path exists
        """
        path: Optional[list[UUID]] = self.graph.find_shortest_path(
            entry_host_id,
            target_host_id,
            weight="weight"
        )

        if not path:
            return None

        return self._build_attack_path(path, "shortest")

    def find_highest_impact_path(
        self,
        entry_host_id: UUID,
        max_hops: int = 10
    ) -> Optional[AttackPath]:
        """
        Find path to highest impact target.

        Considers privilege gain and criticality.

        Args:
            entry_host_id: Starting host
            max_hops: Maximum path length

        Returns:
            AttackPath or None
        """
        all_paths: list[list[UUID]] = []

        for node_id in self.graph._node_map.keys():
            if node_id == entry_host_id:
                continue

            paths: list[list[UUID]] = self.graph.find_all_paths(
                entry_host_id,
                node_id,
                cutoff=max_hops
            )
            all_paths.extend(paths)

        if not all_paths:
            return None

        scored_paths: list[tuple[list[UUID], float]] = []

        for path in all_paths:
            score: float = self._calculate_path_impact(path)
            scored_paths.append((path, score))

        scored_paths.sort(key=lambda x: x[1], reverse=True)

        best_path: list[UUID] = scored_paths[0][0]
        return self._build_attack_path(best_path, "highest_impact")

    def find_lowest_complexity_path(
        self,
        entry_host_id: UUID,
        target_host_id: UUID
    ) -> Optional[AttackPath]:
        """
        Find path with lowest exploitation complexity.

        Prefers high maturity exploits and simple chains.

        Args:
            entry_host_id: Starting host
            target_host_id: Target host

        Returns:
            AttackPath or None
        """
        all_paths: list[list[UUID]] = self.graph.find_all_paths(
            entry_host_id,
            target_host_id,
            cutoff=10
        )

        if not all_paths:
            return None

        scored_paths: list[tuple[list[UUID], float]] = []

        for path in all_paths:
            complexity: float = self._calculate_path_complexity(path)
            scored_paths.append((path, 1.0 - complexity))

        scored_paths.sort(key=lambda x: x[1], reverse=True)

        best_path: list[UUID] = scored_paths[0][0]
        return self._build_attack_path(best_path, "lowest_complexity")

    def detect_privilege_escalation_chains(
        self,
        host_id: UUID
    ) -> list[AttackPath]:
        """
        Detect privilege escalation paths on a single host.

        Args:
            host_id: Host to analyze

        Returns:
            List of privilege escalation paths
        """
        chains: list[AttackPath] = []

        priv_nodes: list[str] = []

        for node_id, data in self.graph.graph.nodes(data=True):
            if data.get("node_type") == "privilege":
                host_ref: Optional[str] = data.get("host_id")
                if host_ref and str(host_id) == host_ref:
                    priv_nodes.append(node_id)

        if len(priv_nodes) < 2:
            return chains

        for i, start_node in enumerate(priv_nodes):
            for end_node in priv_nodes[i+1:]:
                try:
                    path: list[str] = nx.shortest_path(
                        self.graph.graph,
                        start_node,
                        end_node,
                        weight="weight"
                    )

                    entity_path: list[UUID] = []
                    for node_id in path:
                        node_data: dict[str, Any] = self.graph.graph.nodes[node_id]
                        entity_id_str: Optional[str] = node_data.get("entity_id")
                        if entity_id_str:
                            entity_path.append(UUID(entity_id_str))

                    if len(entity_path) >= 2:
                        attack_path: AttackPath = self._build_attack_path(
                            entity_path,
                            "privilege_escalation"
                        )
                        chains.append(attack_path)

                except nx.NetworkXNoPath:
                    continue

        return chains

    def find_lateral_pivot_paths(
        self,
        compromised_host_id: UUID,
        max_hops: int = 3
    ) -> list[AttackPath]:
        """
        Find lateral movement opportunities from compromised host.

        Args:
            compromised_host_id: Currently compromised host
            max_hops: Maximum pivot distance

        Returns:
            List of pivot paths
        """
        paths: list[AttackPath] = []

        for node_id in self.graph._node_map.keys():
            if node_id == compromised_host_id:
                continue

            pivot_paths: list[list[UUID]] = self.graph.find_all_paths(
                compromised_host_id,
                node_id,
                cutoff=max_hops
            )

            for path in pivot_paths:
                if len(path) >= 2:
                    attack_path: AttackPath = self._build_attack_path(path, "lateral_pivot")
                    paths.append(attack_path)

        paths.sort(key=lambda p: p.pivot_score, reverse=True)
        return paths[:10]

    def _calculate_path_impact(self, path: list[UUID]) -> float:
        """Calculate impact score for a path."""
        if not path:
            return 0.0

        total_criticality: float = 0.0
        max_privilege: PrivilegeLevel = PrivilegeLevel.NONE

        for entity_id in path:
            node_data: Optional[dict[str, Any]] = self.graph.get_node(entity_id)
            if not node_data:
                continue

            criticality: float = node_data.get("criticality", 0.0)
            total_criticality += criticality

            node_type: str = node_data.get("node_type", "")
            if node_type == "privilege":
                priv_str: str = node_data.get("privilege_level", "none")
                try:
                    priv: PrivilegeLevel = PrivilegeLevel(priv_str)
                    if self._privilege_value(priv) > self._privilege_value(max_privilege):
                        max_privilege = priv
                except ValueError:
                    pass

        privilege_factor: float = self._privilege_value(max_privilege) / 3.0

        return (total_criticality / len(path)) * 0.6 + privilege_factor * 0.4

    def _calculate_path_complexity(self, path: list[UUID]) -> float:
        """Calculate complexity score (lower is simpler)."""
        if not path:
            return 1.0

        complexity: float = 0.0

        for entity_id in path:
            node_data: Optional[dict[str, Any]] = self.graph.get_node(entity_id)
            if not node_data:
                continue

            node_type: str = node_data.get("node_type", "")
            if node_type == "vulnerability":
                maturity_str: str = node_data.get("exploit_maturity", "not_defined")
                maturity_map: dict[str, float] = {
                    "high": 0.1,
                    "functional": 0.3,
                    "proof_of_concept": 0.6,
                    "unproven": 0.9,
                    "not_defined": 0.5,
                }
                complexity += maturity_map.get(maturity_str, 0.5)

        hop_penalty: float = len(path) * 0.05
        return min((complexity / len(path)) + hop_penalty, 1.0)

    def _privilege_value(self, level: PrivilegeLevel) -> int:
        """Convert privilege level to numeric value."""
        values: dict[PrivilegeLevel, int] = {
            PrivilegeLevel.NONE: 0,
            PrivilegeLevel.USER: 1,
            PrivilegeLevel.ADMIN: 2,
            PrivilegeLevel.SYSTEM: 3,
        }
        return values.get(level, 0)

    def _build_attack_path(
        self,
        entity_path: list[UUID],
        path_type: str
    ) -> AttackPath:
        """Build AttackPath object from entity path."""
        edges: list[tuple[UUID, UUID, str]] = []

        for i in range(len(entity_path) - 1):
            source: UUID = entity_path[i]
            target: UUID = entity_path[i + 1]

            source_node: Optional[str] = self.graph._node_map.get(source)
            target_node: Optional[str] = self.graph._node_map.get(target)

            if source_node and target_node:
                edge_data: dict[str, Any] = self.graph.graph.edges.get(
                    (source_node, target_node),
                    {}
                )
                edge_type: str = edge_data.get("edge_type", "unknown")
                edges.append((source, target, edge_type))

        impact_score: float = self._calculate_path_impact(entity_path)
        complexity_score: float = self._calculate_path_complexity(entity_path)

        pivot_score: float = max(0.0, impact_score - (complexity_score * 0.3))

        return AttackPath(
            source_host_id=entity_path[0],
            target_host_id=entity_path[-1],
            path=entity_path,
            edges=edges,
            pivot_score=round(pivot_score, 4),
            complexity_score=round(complexity_score, 4),
            impact_score=round(impact_score, 4),
            privilege_gain=PrivilegeLevel.USER,
            estimated_time=len(entity_path) * 15,
        )

    def get_top_pivot_paths(
        self,
        entry_points: list[UUID],
        top_n: int = 5
    ) -> list[AttackPath]:
        """
        Get top N pivot paths from entry points.

        Args:
            entry_points: List of entry point host IDs
            top_n: Number of top paths to return

        Returns:
            List of top attack paths
        """
        all_paths: list[AttackPath] = []

        for entry_id in entry_points:
            high_impact: Optional[AttackPath] = self.find_highest_impact_path(entry_id)
            if high_impact:
                all_paths.append(high_impact)

            lateral: list[AttackPath] = self.find_lateral_pivot_paths(entry_id)
            all_paths.extend(lateral)

        all_paths.sort(key=lambda p: p.pivot_score, reverse=True)

        seen: set[tuple[UUID, UUID]] = set()
        unique_paths: list[AttackPath] = []

        for path in all_paths:
            key: tuple[UUID, UUID] = (path.source_host_id, path.target_host_id)
            if key not in seen:
                seen.add(key)
                unique_paths.append(path)

        return unique_paths[:top_n]
