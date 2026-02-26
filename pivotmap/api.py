"""
PivotMap FastAPI interface.

API Endpoints:
- POST /import: Import scan results
- POST /analyze: Build attack graph
- GET /paths: Get attack paths
- GET /report: Generate report
- GET /graph: Export graph data
- GET /cve/{id}: Get CVE details
"""

from typing import Any, Optional
from uuid import UUID

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

from pivotmap.core.graph_builder import AttackGraph
from pivotmap.core.scorer import PivotScorer
from pivotmap.engine.pivot_engine import PivotEngine
from pivotmap.ingest.normalizer import DataNormalizer
from pivotmap.knowledge.cve_loader import CVELoader
from pivotmap.reporting.markdown import MarkdownReporter
from pivotmap.reporting.html import HTMLReporter

app: FastAPI = FastAPI(
    title="PivotMap API",
    description="Attack Path Intelligence Engine",
    version="0.1.0",
)

# Global state (in production, use proper state management)
_graph: Optional[AttackGraph] = None
_normalizer: Optional[DataNormalizer] = None
_cve_loader: Optional[CVELoader] = None


@app.get("/")
async def root() -> dict[str, str]:
    """API root endpoint."""
    return {
        "name": "PivotMap",
        "version": "0.1.0",
        "description": "Attack Path Intelligence Engine",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/import")
async def import_scan(
    file: UploadFile = File(...),
    format: str = "auto",
) -> dict[str, Any]:
    """
    Import scan results file.

    Supports Nmap XML and Nuclei JSON formats.
    """
    global _normalizer

    if _normalizer is None:
        _normalizer = DataNormalizer()

    content: bytes = await file.read()
    content_str: str = content.decode("utf-8")

    filename: str = file.filename or "unknown"

    try:
        if format == "auto":
            if filename.endswith(".xml"):
                format = "nmap"
            elif filename.endswith(".json"):
                format = "nuclei"

        if format == "nmap":
            from pivotmap.ingest.nmap import NmapParser
            parser = NmapParser()
            result = parser.parse_string(content_str)
            for host in parser.get_hosts():
                _normalizer._merge_hosts([host])
            for service in parser.get_services():
                _normalizer._merge_services([service])

        elif format == "nuclei":
            from pivotmap.ingest.nuclei import NucleiParser
            parser = NucleiParser()
            result = parser.parse_string(content_str)
            for host in parser.get_hosts():
                _normalizer._merge_hosts([host])
            for service in parser.get_services():
                _normalizer._merge_services([service])
            for vuln in parser.get_vulnerabilities():
                _normalizer._merge_vulnerabilities([vuln])


        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format}")

        return {
            "success": True,
            "format": format,
            "hosts": result.host_count,
            "services": result.service_count,
            "vulnerabilities": result.vulnerability_count,
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/analyze")
async def analyze() -> dict[str, Any]:
    """
    Build attack graph from imported data.
    """
    global _graph, _normalizer

    if _normalizer is None:
        raise HTTPException(status_code=400, detail="No data imported. Use /import first.")

    _graph = AttackGraph()
    scorer: PivotScorer = PivotScorer()

    for host in _normalizer.get_all_hosts():
        _graph.add_host(host)

        host_services: list = _normalizer.get_services_by_host(host.id)
        for service in host_services:
            criticality: float = scorer.calculate_service_criticality(service)
            _graph.add_service(service, host, criticality=criticality)

    for vuln in _normalizer.get_all_vulnerabilities():
        host_id: Optional[UUID] = vuln.host_id
        service_id: Optional[UUID] = vuln.service_id

        service: Optional = None
        if service_id:
            for svc in _normalizer.get_all_services():
                if svc.id == service_id:
                    service = svc
                    host_id = svc.host_id
                    break

        host: Optional = None
        if host_id:
            for h in _normalizer.get_all_hosts():
                if h.id == host_id:
                    host = h
                    break

        if service or host:
            from pivotmap.core.models import Host as HostModel
            exposure = host.exposure if isinstance(host, HostModel) else None
            score: float = scorer.score_vulnerability(vuln, service, exposure)
            _graph.add_vulnerability(vuln, service, host, criticality=score)

    stats: dict = _graph.get_statistics()

    return {
        "success": True,
        "nodes": stats["node_count"],
        "edges": stats["edge_count"],
        "hosts": stats["host_nodes"],
        "services": stats["service_nodes"],
        "vulnerabilities": stats["vulnerability_nodes"],
        "density": stats["density"],
    }


@app.get("/paths")
async def get_paths(
    top: int = 5,
    from_host: Optional[str] = None,
    to_host: Optional[str] = None,
) -> dict[str, Any]:
    """
    Get top attack paths.
    """
    global _graph

    if _graph is None:
        raise HTTPException(status_code=400, detail="No graph built. Use /analyze first.")

    engine: PivotEngine = PivotEngine(_graph)

    paths: list = []
    entry_points: list = []

    if from_host:
        try:
            entry_id: UUID = UUID(from_host)
            entry_points.append(entry_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_host UUID")
    else:
        from pivotmap.engine.path_finder import PathFinder
        finder: PathFinder = PathFinder(_graph)
        entry_points = finder.find_entry_points()[:5]

    if to_host:
        try:
            target_id: UUID = UUID(to_host)
            for entry in entry_points:
                path = engine.find_shortest_compromise_path(entry, target_id)
                if path:
                    paths.append(path)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_host UUID")
    else:
        paths = engine.get_top_pivot_paths(entry_points, top_n=top)

    return {
        "paths": [
            {
                "id": str(p.id),
                "source": str(p.source_host_id),
                "target": str(p.target_host_id),
                "pivot_score": p.pivot_score,
                "impact_score": p.impact_score,
                "complexity_score": p.complexity_score,
                "hops": len(p.path) - 1,
                "sequence": [str(n) for n in p.path],
            }
            for p in paths
        ],
        "count": len(paths),
    }


@app.get("/report")
async def get_report(
    format: str = "markdown",
) -> PlainTextResponse | JSONResponse:
    """
    Generate attack path report.
    """
    global _graph

    if _graph is None:
        raise HTTPException(status_code=400, detail="No graph built. Use /analyze first.")

    if format == "markdown":
        reporter: MarkdownReporter = MarkdownReporter(_graph)
        content: str = reporter.generate()
        return PlainTextResponse(content, media_type="text/markdown")

    elif format == "html":
        reporter: HTMLReporter = HTMLReporter(_graph)
        content: str = reporter.generate()
        return PlainTextResponse(content, media_type="text/html")

    elif format == "json":
        return JSONResponse({
            "graph": _graph.to_dict(),
            "statistics": _graph.get_statistics(),
        })

    else:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}")


@app.get("/graph")
async def get_graph() -> dict[str, Any]:
    """
    Export graph data in JSON format.
    """
    global _graph

    if _graph is None:
        raise HTTPException(status_code=400, detail="No graph built. Use /analyze first.")

    return _graph.to_dict()


@app.get("/cve/{cve_id}")
async def get_cve(cve_id: str) -> dict[str, Any]:
    """
    Get CVE details from loaded database.
    """
    global _cve_loader

    if _cve_loader is None:
        _cve_loader = CVELoader()

    cve_data: Optional[dict] = _cve_loader.get_cve(cve_id)

    if cve_data is None:
        raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")

    return {
        "cve_id": cve_id,
        "data": cve_data,
    }


@app.get("/stats")
async def get_stats() -> dict[str, Any]:
    """
    Get current analysis statistics.
    """
    global _graph, _normalizer

    stats: dict[str, Any] = {
        "has_graph": _graph is not None,
        "has_data": _normalizer is not None,
    }

    if _graph:
        stats["graph"] = _graph.get_statistics()

    if _normalizer:
        stats["data"] = {
            "hosts": len(_normalizer.get_all_hosts()),
            "services": len(_normalizer.get_all_services()),
            "vulnerabilities": len(_normalizer.get_all_vulnerabilities()),
        }

    return stats
