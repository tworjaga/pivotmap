# PivotMap

Attack Path Intelligence Engine

From exposure to compromise.

## Overview

PivotMap is an open-source Python-based attack path intelligence engine for offensive security professionals. It does not perform active scanning. Instead, it ingests scan results, correlates vulnerabilities, builds an attack graph, and identifies realistic compromise paths.

## Core Principles

- Vulnerability lists are not intelligence
- CVSS alone is insufficient
- Attack paths matter more than raw findings
- Context determines exploitability
- Correlation over enumeration

## Features

- **Ingestion Layer**: Parse Nmap XML and Nuclei JSON scan results
- **Correlation Engine**: Match services to CVEs with fuzzy version matching
- **Graph Engine**: Build directed attack graphs with networkx
- **Pivot Engine**: Compute shortest, highest impact, and lowest complexity paths
- **PivotScore System**: Multi-factor scoring (exploitability × exposure × privilege × network position × criticality)
- **Reporting**: Generate Markdown, HTML, and JSON reports

## Installation

```bash
pip install pivotmap
```

Or from source:

```bash
git clone https://github.com/tworjaga/pivotmap.git
cd pivotmap
pip install -e .
```

## Quick Start

### CLI Usage

```bash
# Import scan results
pivotmap import scan.xml
pivotmap import vulns.json --format nuclei

# Build attack graph
pivotmap analyze --nmap scan.xml --nuclei vulns.json

# Find top attack paths
pivotmap paths --top 10

# Generate report
pivotmap report --format html --output report.html
```

### API Usage

```bash
# Start API server
uvicorn pivotmap.api:app --reload

# Import and analyze
curl -X POST -F "file=@scan.xml" http://localhost:8000/import
curl -X POST http://localhost:8000/analyze

# Get attack paths
curl http://localhost:8000/paths?top=5

# Generate report
curl http://localhost:8000/report?format=markdown
```

## Architecture

```
pivotmap/
├── core/           # Data models, scoring, graph builder
├── ingest/         # Nmap/Nuclei parsers
├── knowledge/      # CVE database, exploit metadata
├── engine/         # Pivot engine, path finder
├── reporting/      # Report generators
├── cli.py          # Command-line interface
├── api.py          # FastAPI endpoints
└── config.py       # Configuration management
```

## Requirements

- Python 3.12+
- FastAPI
- Typer
- Rich
- Pydantic
- SQLModel
- networkx
- httpx

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome. Please follow conventional commits format.

## Contact

- GitHub: https://github.com/tworjaga
- Telegram: @al7exy
