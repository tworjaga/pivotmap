"""
Ingestion layer for scan data parsing.

Supports Nmap XML and Nuclei JSON formats.
"""

from pivotmap.ingest.nmap import NmapParser
from pivotmap.ingest.nuclei import NucleiParser
from pivotmap.ingest.normalizer import DataNormalizer

__all__ = [
    "DataNormalizer",
    "NmapParser",
    "NucleiParser",
]
