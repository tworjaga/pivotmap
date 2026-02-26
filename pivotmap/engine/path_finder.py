"""
Path finding algorithms for attack graph traversal.

Implements Dijkstra, BFS, and custom path ranking algorithms.
"""

from typing import Any, Callable, Optional
from uuid import UUID

import networkx as nx

from pivotmap.core.graph_builder import AttackGraph


class PathFinder:
    """
    Advanced path finding with custom constraints and ranking.
    """

    def __init__(self, graph: AttackGraph) -> None:
        """
        Initialize path finder.

        Args:
            graph: Attack graph instance
        """
        self.graph: AttackGraph = graph

    def find_shortest_path(
        self,
        source: UUID,
        target: UUID,
        weight: str = "weight"
    ) -> Optional[list[UUID]]:
        """
        Find shortest path using Dijkstra.

        Args:
            source: Source node ID
            target: Target node ID
            weight: Edge attribute to use as weight

        Returns:
            Path as list of UUIDs or None
        """
        return self.graph.find_shortest_path(source, target, weight)

    def find_all_paths(
        self,
        source: UUID,
        target: UUID,
        cutoff: int = 10
    ) -> list[list[UUID]]:
        """
        Find all simple paths up to length cutoff.

        Args:
            source: Source node ID
            target: Target node ID
            cutoff: Maximum path length

        Returns:
            List of paths
        """
        return self.graph.find_all_paths(source, target, cutoff)

    def find_paths_with_constraint(
        self,
        source: UUID,
        target: UUID,
        constraint: Callable[[list[UUID]], bool],
        max_paths: int = 100
    ) -> list[list[UUID]]:
        """
        Find paths matching custom constraint function.

        Args:
            source: Source node ID
            target: Target node ID
            constraint: Function that returns True for valid paths
            max_paths: Maximum paths to return

        Returns:
            Filtered list of paths
        """
        all_paths: list[list[UUID]] = self.find_all_paths(source, target, cutoff=15)

        valid_paths: list[list[UUID]] = []
        for path in all_paths:
            if constraint(path):
                valid_paths.append(path)
                if len(valid_paths) >= max_paths:
                    break

        return valid_paths

    def find_paths_avoiding_node(
        self,
        source: UUID,
        target: UUID,
        avoid: set[UUID],
        cutoff: int = 10
    ) -> list[list[UUID]]:
        """
        Find paths that avoid specific nodes.

        Args:
            source: Source node ID
            target: Target node ID
            avoid: Set of node IDs to avoid
            cutoff: Maximum path length

        Returns:
            List of valid paths
        """
        def constraint(path: list[UUID]) -> bool:
            return not any(node in avoid for node in path)

        return self.find_paths_with_constraint(source, target, constraint, max_paths=50)

    def find_paths_through_node(
        self,
        source: UUID,
        target: UUID,
        required: UUID,
        cutoff: int = 10
    ) -> list[list[UUID]]:
        """
        Find paths that must pass through specific node.

        Args:
            source: Source node ID
            target: Target node ID
            required: Node that must be in path
            cutoff: Maximum path length

        Returns:
            List of valid paths
        """
        def constraint(path: list[UUID]) -> bool:
            return required in path

        return self.find_paths_with_constraint(source, target, constraint, max_paths=50)

    def find_minimum_hops(self, source: UUID, target: UUID) -> int:
        """
        Find minimum number of hops between nodes.

        Args:
            source: Source node ID
            target: Target node ID

        Returns:
            Minimum hop count or -1 if no path
        """
        path: Optional[list[UUID]] = self.find_shortest_path(source, target)

        if not path:
            return -1

        return len(path) - 1

    def find_reachable_nodes(
        self,
        source: UUID,
        max_depth: int = 5
    ) -> dict[UUID, int]:
        """
        Find all nodes reachable within max_depth hops.

        Args:
            source: Source node ID
            max_depth: Maximum traversal depth

        Returns:
            Dictionary of node_id -> hop_count
        """
        source_node: Optional[str] = self.graph._node_map.get(source)
        if not source_node:
            return {}

        lengths: dict[str, int] = nx.single_source_shortest_path_length(
            self.graph.graph,
            source_node,
            cutoff=max_depth
        )

        result: dict[UUID, int] = {}
        for node_id, distance in lengths.items():
            node_data: dict[str, Any] = self.graph.graph.nodes[node_id]
            entity_id_str: Optional[str] = node_data.get("entity_id")
            if entity_id_str:
                result[UUID(entity_id_str)] = distance

        return result

    def find_entry_points(self) -> list[UUID]:
        """
        Find potential entry points (nodes with no incoming edges).

        Returns:
            List of entry point node IDs
        """
        entry_points: list[UUID] = []

        for node_id in self.graph.graph.nodes():
            if self.graph.graph.in_degree(node_id) == 0:
                node_data: dict[str, Any] = self.graph.graph.nodes[node_id]
                entity_id_str: Optional[str] = node_data.get("entity_id")
                if entity_id_str:
                    entry_points.append(UUID(entity_id_str))

        return entry_points

    def find_critical_targets(self, top_n: int = 10) -> list[tuple[UUID, float]]:
        """
        Find critical target nodes by centrality.

        Args:
            top_n: Number of top targets to return

        Returns:
            List of (node_id, centrality_score) tuples
        """
        return self.graph.get_critical_nodes(top_n)

    def rank_paths_by_weight(
        self,
        paths: list[list[UUID]],
        weight_func: Optional[Callable[[list[UUID]], float]] = None
    ) -> list[tuple[list[UUID], float]]:
        """
        Rank paths by custom weight function.

        Args:
            paths: List of paths to rank
            weight_func: Function to calculate path weight (default: sum of edge weights)

        Returns:
            List of (path, weight) tuples sorted by weight
        """
        if weight_func is None:
            def default_weight(path: list[UUID]) -> float:
                total: float = 0.0
                for i in range(len(path) - 1):
                    source: UUID = path[i]
                    target: UUID = path[i + 1]

                    source_node: Optional[str] = self.graph._node_map.get(source)
                    target_node: Optional[str] = self.graph._node_map.get(target)

                    if source_node and target_node:
                        edge_data: dict[str, Any] = self.graph.graph.edges.get(
                            (source_node, target_node),
                            {}
                        )
                        total += edge_data.get("weight", 1.0)

                return total

            weight_func = default_weight

        scored: list[tuple[list[UUID], float]] = [
            (path, weight_func(path)) for path in paths
        ]

        scored.sort(key=lambda x: x[1])
        return scored

    def path_to_edges(self, path: list[UUID]) -> list[tuple[UUID, UUID, str]]:
        """
        Convert path to list of edges with types.

        Args:
            path: List of node IDs

        Returns:
            List of (source, target, edge_type) tuples
        """
        edges: list[tuple[UUID, UUID, str]] = []

        for i in range(len(path) - 1):
            source: UUID = path[i]
            target: UUID = path[i + 1]

            source_node: Optional[str] = self.graph._node_map.get(source)
            target_node: Optional[str] = self.graph._node_map.get(target)

            if source_node and target_node:
                edge_data: dict[str, Any] = self.graph.graph.edges.get(
                    (source_node, target_node),
                    {}
                )
                edge_type: str = edge_data.get("edge_type", "unknown")
                edges.append((source, target, edge_type))

        return edges

    def get_path_statistics(self, path: list[UUID]) -> dict[str, Any]:
        """
        Get statistics for a path.

        Args:
            path: List of node IDs

        Returns:
            Dictionary of path statistics
        """
        if not path:
            return {
                "length": 0,
                "hops": 0,
                "node_types": {},
                "total_weight": 0.0,
            }

        node_types: dict[str, int] = {}
        total_weight: float = 0.0

        for entity_id in path:
            node_data: Optional[dict[str, Any]] = self.graph.get_node(entity_id)
            if node_data:
                node_type: str = node_data.get("node_type", "unknown")
                node_types[node_type] = node_types.get(node_type, 0) + 1

        edges: list[tuple[UUID, UUID, str]] = self.path_to_edges(path)
        for source, target, _ in edges:
            source_node: Optional[str] = self.graph._node_map.get(source)
            target_node: Optional[str] = self.graph._node_map.get(target)

            if source_node and target_node:
                edge_data: dict[str, Any] = self.graph.graph.edges.get(
                    (source_node, target_node),
                    {}
                )
                total_weight += edge_data.get("weight", 1.0)

        return {
            "length": len(path),
            "hops": len(path) - 1,
            "node_types": node_types,
            "total_weight": round(total_weight, 4),
            "edge_count": len(edges),
        }
