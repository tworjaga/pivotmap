"""
Markdown report generator.

Creates human-readable attack path reports in Markdown format.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from pivotmap.core.models import AttackPath, Host, Service, Vulnerability
from pivotmap.core.graph_builder import AttackGraph


class MarkdownReporter:
    """
    Generate Markdown reports from attack analysis results.
    """

    def __init__(self, graph: AttackGraph) -> None:
        """
        Initialize reporter.

        Args:
            graph: Attack graph with analysis results
        """
        self.graph: AttackGraph = graph
        self.report_lines: list[str] = []

    def generate(
        self,
        title: str = "PivotMap Attack Path Analysis",
        paths: Optional[list[AttackPath]] = None,
        hosts: Optional[list[Host]] = None,
        vulnerabilities: Optional[list[Vulnerability]] = None
    ) -> str:
        """
        Generate complete Markdown report.

        Args:
            title: Report title
            paths: Attack paths to include
            hosts: Hosts to document
            vulnerabilities: Vulnerabilities to document

        Returns:
            Markdown formatted string
        """
        self.report_lines = []

        self._add_header(title)
        self._add_metadata()
        self._add_attack_surface_overview()
        self._add_critical_nodes()

        if paths:
            self._add_top_pivot_paths(paths)

        if vulnerabilities:
            self._add_exploit_maturity_summary(vulnerabilities)

        if paths:
            self._add_privilege_escalation_chains(paths)

        self._add_recommendations()

        return "\n".join(self.report_lines)

    def _add_header(self, title: str) -> None:
        """Add report header."""
        self.report_lines.extend([
            f"# {title}",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "---",
            "",
        ])

    def _add_metadata(self) -> None:
        """Add report metadata section."""
        stats: dict[str, Any] = self.graph.get_statistics()

        self.report_lines.extend([
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Nodes | {stats.get('node_count', 0)} |",
            f"| Total Edges | {stats.get('edge_count', 0)} |",
            f"| Hosts | {stats.get('host_nodes', 0)} |",
            f"| Services | {stats.get('service_nodes', 0)} |",
            f"| Vulnerabilities | {stats.get('vulnerability_nodes', 0)} |",
            f"| Graph Density | {stats.get('density', 0.0)} |",
            "",
        ])

    def _add_attack_surface_overview(self) -> None:
        """Add attack surface section."""
        self.report_lines.extend([
            "## Attack Surface Overview",
            "",
            "### Network Segments",
            "",
        ])

        segments: dict[str, int] = {}
        for node_id, data in self.graph.graph.nodes(data=True):
            if data.get("node_type") == "host":
                exposure: str = data.get("exposure", "unknown")
                segments[exposure] = segments.get(exposure, 0) + 1

        if segments:
            for segment, count in sorted(segments.items()):
                self.report_lines.append(f"- **{segment.upper()}**: {count} hosts")
        else:
            self.report_lines.append("- No segment data available")

        self.report_lines.append("")

    def _add_critical_nodes(self) -> None:
        """Add critical nodes section."""
        self.report_lines.extend([
            "## Critical Nodes",
            "",
            "Nodes with highest centrality (potential pivot points):",
            "",
        ])

        critical: list[tuple[UUID, float]] = self.graph.get_critical_nodes(top_n=10)

        if critical:
            self.report_lines.append("| Rank | Node | Type | Centrality |")
            self.report_lines.append("|------|------|------|------------|")

            for rank, (node_id, score) in enumerate(critical, 1):
                node_data: Optional[dict[str, Any]] = self.graph.get_node(node_id)
                if node_data:
                    node_type: str = node_data.get("node_type", "unknown")
                    label: str = node_data.get("label", str(node_id))[:30]
                    self.report_lines.append(
                        f"| {rank} | {label} | {node_type} | {score:.4f} |"
                    )

        else:
            self.report_lines.append("No critical nodes identified.")

        self.report_lines.append("")

    def _add_top_pivot_paths(self, paths: list[AttackPath]) -> None:
        """Add top pivot paths section."""
        self.report_lines.extend([
            "## Top Pivot Paths",
            "",
            f"**Total Paths Analyzed:** {len(paths)}",
            "",
        ])

        sorted_paths: list[AttackPath] = sorted(
            paths,
            key=lambda p: p.pivot_score,
            reverse=True
        )[:10]

        for rank, path in enumerate(sorted_paths, 1):
            self.report_lines.extend([
                f"### Path {rank}: {path.source_host_id} -> {path.target_host_id}",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Pivot Score | {path.pivot_score:.4f} |",
                f"| Impact Score | {path.impact_score:.4f} |",
                f"| Complexity | {path.complexity_score:.4f} |",
                f"| Hops | {len(path.path) - 1} |",
                f"| Est. Time | {path.estimated_time or 'N/A'} min |",
                "",
                "**Path Sequence:**",
                "",
            ])

            for i, node_id in enumerate(path.path):
                node_data: Optional[dict[str, Any]] = self.graph.get_node(node_id)
                if node_data:
                    label: str = node_data.get("label", str(node_id))
                    self.report_lines.append(f"{i + 1}. {label}")

            self.report_lines.append("")

    def _add_exploit_maturity_summary(
        self,
        vulnerabilities: list[Vulnerability]
    ) -> None:
        """Add exploit maturity section."""
        self.report_lines.extend([
            "## Exploit Maturity Summary",
            "",
        ])

        maturity_counts: dict[str, int] = {}
        for vuln in vulnerabilities:
            mat: str = vuln.exploit_maturity.value
            maturity_counts[mat] = maturity_counts.get(mat, 0) + 1

        if maturity_counts:
            self.report_lines.append("| Maturity Level | Count |")
            self.report_lines.append("|----------------|-------|")

            for level, count in sorted(maturity_counts.items()):
                self.report_lines.append(f"| {level} | {count} |")

        self.report_lines.append("")

    def _add_privilege_escalation_chains(self, paths: list[AttackPath]) -> None:
        """Add privilege escalation section."""
        priv_paths: list[AttackPath] = [
            p for p in paths if p.privilege_gain.value != "none"
        ]

        if not priv_paths:
            return

        self.report_lines.extend([
            "## Privilege Escalation Chains",
            "",
            f"**Detected Chains:** {len(priv_paths)}",
            "",
        ])

        for path in priv_paths[:5]:
            self.report_lines.append(
                f"- {path.source_host_id} -> {path.target_host_id} "
                f"(Gain: {path.privilege_gain.value})"
            )

        self.report_lines.append("")

    def _add_recommendations(self) -> None:
        """Add recommendations section."""
        self.report_lines.extend([
            "## Recommendations",
            "",
            "### Immediate Actions",
            "",
            "1. **Patch Critical Vulnerabilities**: Prioritize vulnerabilities with",
            "   high exploit maturity and external exposure.",
            "",
            "2. **Segment Critical Assets**: Isolate high-value targets from",
            "   entry points to increase attack path complexity.",
            "",
            "3. **Monitor Pivot Points**: Implement detection for lateral",
            "   movement between identified critical nodes.",
            "",
            "### Strategic Improvements",
            "",
            "1. **Reduce Attack Surface**: Remove unnecessary services and",
            "   close unused ports on externally exposed hosts.",
            "",
            "2. **Implement Defense in Depth**: Layer security controls",
            "   to increase complexity of privilege escalation chains.",
            "",
            "3. **Regular Assessment**: Continuously update attack graphs",
            "   as new vulnerabilities and network changes occur.",
            "",
        ])

    def save(self, output_path: str) -> None:
        """
        Save report to file.

        Args:
            output_path: Path to save Markdown file
        """
        content: str = "\n".join(self.report_lines)
        Path(output_path).write_text(content, encoding="utf-8")

    def to_dict(self) -> dict[str, Any]:
        """Export report data as dictionary."""
        return {
            "content": "\n".join(self.report_lines),
            "generated_at": datetime.utcnow().isoformat(),
            "graph_stats": self.graph.get_statistics(),
        }
