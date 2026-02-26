"""
HTML report generator with visualization support.

Creates interactive HTML reports with attack path visualizations.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from jinja2 import Template

from pivotmap.core.models import AttackPath, Host, Vulnerability
from pivotmap.core.graph_builder import AttackGraph


HTML_TEMPLATE: str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-tertiary: #0f3460;
            --accent: #e94560;
            --text-primary: #eaeaea;
            --text-secondary: #a0a0a0;
            --border: #2d3748;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        header {
            border-bottom: 2px solid var(--accent);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }

        h1 {
            color: var(--accent);
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }

        .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent);
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        h2 {
            color: var(--accent);
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }

        h3 {
            color: var(--text-primary);
            margin: 1rem 0 0.5rem 0;
            font-size: 1.2rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }

        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-tertiary);
            color: var(--accent);
            font-weight: 600;
        }

        tr:hover {
            background: var(--bg-tertiary);
        }

        .path-card {
            background: var(--bg-tertiary);
            border-left: 4px solid var(--accent);
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 0 4px 4px 0;
        }

        .path-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .path-score {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent);
        }

        .path-sequence {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .node-badge {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .arrow {
            color: var(--accent);
        }

        .severity-critical { color: #ff4444; }
        .severity-high { color: #ff8800; }
        .severity-medium { color: #ffcc00; }
        .severity-low { color: #00ccff; }

        .recommendations {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 4px;
        }

        .recommendations ul {
            margin-left: 1.5rem;
        }

        .recommendations li {
            margin: 0.5rem 0;
        }

        footer {
            text-align: center;
            color: var(--text-secondary);
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ title }}</h1>
            <div class="meta">
                Generated: {{ generated_at }} | PivotMap v{{ version }}
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.node_count }}</div>
                <div class="stat-label">Total Nodes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.edge_count }}</div>
                <div class="stat-label">Edges</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.host_nodes }}</div>
                <div class="stat-label">Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ stats.vulnerability_nodes }}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>

        <section>
            <h2>Attack Surface Overview</h2>
            <table>
                <thead>
                    <tr>
                        <th>Network Segment</th>
                        <th>Host Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for segment, count in segments.items() %}
                    <tr>
                        <td>{{ segment.upper() }}</td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Critical Nodes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Node</th>
                        <th>Type</th>
                        <th>Centrality</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rank, node in critical_nodes %}
                    <tr>
                        <td>{{ rank }}</td>
                        <td>{{ node.label }}</td>
                        <td>{{ node.type }}</td>
                        <td>{{ "%.4f"|format(node.score) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Top Pivot Paths</h2>
            {% for path in paths %}
            <div class="path-card">
                <div class="path-header">
                    <h3>Path {{ loop.index }}: {{ path.source }} -> {{ path.target }}</h3>
                    <div class="path-score">{{ "%.3f"|format(path.pivot_score) }}</div>
                </div>
                <table>
                    <tr>
                        <td>Impact Score</td>
                        <td>{{ "%.3f"|format(path.impact_score) }}</td>
                    </tr>
                    <tr>
                        <td>Complexity</td>
                        <td>{{ "%.3f"|format(path.complexity_score) }}</td>
                    </tr>
                    <tr>
                        <td>Hops</td>
                        <td>{{ path.hops }}</td>
                    </tr>
                </table>
                <div class="path-sequence">
                    {% for node in path.sequence %}
                    <span class="node-badge">{{ node }}</span>
                    {% if not loop.last %}
                    <span class="arrow">-></span>
                    {% endif %}
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </section>

        <section>
            <h2>Recommendations</h2>
            <div class="recommendations">
                <h3>Immediate Actions</h3>
                <ul>
                    <li>Patch critical vulnerabilities with high exploit maturity</li>
                    <li>Segment critical assets from entry points</li>
                    <li>Monitor identified pivot points for lateral movement</li>
                </ul>

                <h3>Strategic Improvements</h3>
                <ul>
                    <li>Reduce attack surface on externally exposed hosts</li>
                    <li>Implement defense in depth for privilege escalation chains</li>
                    <li>Regular assessment and graph updates</li>
                </ul>
            </div>
        </section>

        <footer>
            <p>Generated by PivotMap - Attack Path Intelligence Engine</p>
        </footer>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """
    Generate HTML reports with interactive visualizations.
    """

    def __init__(self, graph: AttackGraph) -> None:
        """
        Initialize reporter.

        Args:
            graph: Attack graph with analysis results
        """
        self.graph: AttackGraph = graph
        self.template: Template = Template(HTML_TEMPLATE)

    def generate(
        self,
        title: str = "PivotMap Attack Path Analysis",
        paths: Optional[list[AttackPath]] = None,
        version: str = "0.1.0"
    ) -> str:
        """
        Generate HTML report.

        Args:
            title: Report title
            paths: Attack paths to include
            version: PivotMap version

        Returns:
            HTML formatted string
        """
        stats: dict[str, Any] = self.graph.get_statistics()

        segments: dict[str, int] = {}
        for node_id, data in self.graph.graph.nodes(data=True):
            if data.get("node_type") == "host":
                exposure: str = data.get("exposure", "unknown")
                segments[exposure] = segments.get(exposure, 0) + 1

        critical: list[tuple[UUID, float]] = self.graph.get_critical_nodes(top_n=10)
        critical_nodes: list[tuple[int, dict[str, Any]]] = []

        for rank, (node_id, score) in enumerate(critical, 1):
            node_data: Optional[dict[str, Any]] = self.graph.get_node(node_id)
            if node_data:
                critical_nodes.append((rank, {
                    "label": node_data.get("label", str(node_id))[:30],
                    "type": node_data.get("node_type", "unknown"),
                    "score": score,
                }))

        path_data: list[dict[str, Any]] = []
        if paths:
            sorted_paths: list[AttackPath] = sorted(
                paths,
                key=lambda p: p.pivot_score,
                reverse=True
            )[:10]

            for path in sorted_paths:
                sequence: list[str] = []
                for node_id in path.path:
                    node_data: Optional[dict[str, Any]] = self.graph.get_node(node_id)
                    if node_data:
                        sequence.append(node_data.get("label", str(node_id))[:20])

                path_data.append({
                    "source": str(path.source_host_id)[:8],
                    "target": str(path.target_host_id)[:8],
                    "pivot_score": path.pivot_score,
                    "impact_score": path.impact_score,
                    "complexity_score": path.complexity_score,
                    "hops": len(path.path) - 1,
                    "sequence": sequence,
                })

        return self.template.render(
            title=title,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            version=version,
            stats=stats,
            segments=segments,
            critical_nodes=critical_nodes,
            paths=path_data,
        )

    def save(self, output_path: str, **kwargs: Any) -> None:
        """
        Save HTML report to file.

        Args:
            output_path: Path to save HTML file
            **kwargs: Additional arguments for generate()
        """
        content: str = self.generate(**kwargs)
        Path(output_path).write_text(content, encoding="utf-8")

    def to_dict(self) -> dict[str, Any]:
        """Export report data as dictionary."""
        return {
            "template_loaded": True,
            "graph_stats": self.graph.get_statistics(),
        }
