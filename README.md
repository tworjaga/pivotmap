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

## Download and Installation

### System Requirements

- **Operating System**: Windows 10/11, Linux, macOS
- **Python**: Version 3.12 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended for large graphs)
- **Disk Space**: 500MB for installation, additional space for CVE database

### Method 1: pip install (Recommended)

Install from PyPI when published:

```bash
pip install pivotmap
```

With optional dependencies:

```bash
# With Redis support for background jobs
pip install pivotmap[redis]

# With visualization support
pip install pivotmap[viz]

# With all optional features
pip install pivotmap[all]
```

### Method 2: Install from Source

Clone the repository and install in development mode:

```bash
# Clone repository
git clone https://github.com/tworjaga/pivotmap.git

# Enter directory
cd pivotmap

# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install package in editable mode
pip install -e .
```

### Method 3: Windows Quick Start

For Windows users, use the provided batch file:

```bash
# Download or clone the repository
git clone https://github.com/tworjaga/pivotmap.git
cd pivotmap

# Run the setup script
start.bat
```

The `start.bat` script will:
- Check Python installation
- Create virtual environment
- Install all dependencies
- Install PivotMap in development mode
- Display usage instructions

### Method 4: Docker (Future)

Docker support is planned for containerized deployment.

### Verify Installation

```bash
# Check CLI is working
pivotmap --version

# Check API can be imported
python -c "from pivotmap.api import app; print('API OK')"

# Run tests
pytest tests/
```


## Quick Start

### Step 1: Download Sample Data

Download test scan files to get started:

```bash
# Create test directory
mkdir test_data
cd test_data

# Download sample Nmap XML (replace with your own scan)
# Example: nmap -sV -oX scan.xml target.com

# Download sample Nuclei JSON (replace with your own results)
# Example: nuclei -u target.com -json -o vulns.json
```

### Step 2: CLI Usage

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

### Step 3: API Usage

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

## Dependencies

### Core Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Python | >=3.12 | Runtime |
| FastAPI | >=0.109.0 | API framework |
| Typer | >=0.9.0 | CLI framework |
| Rich | >=13.7.0 | Terminal output |
| Pydantic | >=2.5.0 | Data validation |
| SQLModel | >=0.0.14 | ORM |
| networkx | >=3.2.0 | Graph engine |
| httpx | >=0.26.0 | HTTP client |
| WeasyPrint | >=60.0 | PDF generation |
| PyYAML | >=6.0.1 | YAML parsing |
| Jinja2 | >=3.1.3 | Template engine |

### Optional Dependencies

| Package | Purpose |
|---------|---------|
| redis | Background job queue |
| rq | Job processing |
| pyvis | Interactive graph visualization |
| matplotlib | Static graph plots |

### Download Size

- Source code: ~150KB
- Dependencies: ~50-100MB
- CVE database (optional): ~500MB


## Troubleshooting

### Installation Issues

**Problem**: `pip install` fails with Python version error
**Solution**: Ensure Python 3.12+ is installed: `python --version`

**Problem**: `ModuleNotFoundError` after installation
**Solution**: Install in editable mode: `pip install -e .`

**Problem**: WeasyPrint installation fails
**Solution**: Install system dependencies (GTK+) from https://weasyprint.org

### Runtime Issues

**Problem**: Out of memory with large graphs
**Solution**: Enable graph pruning in config: `graph.pruning_enabled = true`

**Problem**: Slow CVE matching
**Solution**: Use SQLite backend: `cve.backend = "sqlite"`

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome. Please follow conventional commits format.

1. Fork the repository
2. Create feature branch: `git checkout -b feat/new-feature`
3. Commit changes: `git commit -m "feat: add new feature"`
4. Push to branch: `git push origin feat/new-feature`
5. Open Pull Request

## Contact

- **GitHub**: https://github.com/tworjaga
- **Telegram**: @al7exy
- **Project**: https://github.com/tworjaga/pivotmap

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
