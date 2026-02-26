"""
Nuclei JSON parser for vulnerability scan ingestion.

Extracts vulnerability findings from Nuclei JSON output.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID, uuid4

from pivotmap.core.models import (
    ExploitMaturity,
    Host,
    ScanImport,
    Service,
    Vulnerability,
)


class NucleiParser:
    """
    Parse Nuclei JSON scan results.

    Handles Nuclei JSONL format with vulnerability findings.
    """

    def __init__(self) -> None:
        """Initialize parser state."""
        self.findings: list[dict[str, Any]] = []
        self.hosts: list[Host] = []
        self.services: list[Service] = []
        self.vulnerabilities: list[Vulnerability] = []
        self.errors: list[str] = []
        self._host_cache: dict[str, UUID] = {}
        self._service_cache: dict[str, UUID] = {}

    def parse_file(self, file_path: str | Path) -> ScanImport:
        """
        Parse Nuclei JSON/JSONL file.

        Args:
            file_path: Path to Nuclei JSON file

        Returns:
            ScanImport with parsed data summary
        """
        path: Path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Nuclei JSON file not found: {file_path}")

        try:
            content: str = path.read_text(encoding="utf-8")
            return self.parse_string(content, str(path))

        except Exception as e:
            raise ValueError(f"Failed to read file: {e}")

    def parse_string(self, content: str, source_file: Optional[str] = None) -> ScanImport:
        """
        Parse Nuclei JSON content from string.

        Handles both single JSON object and JSONL (newline-delimited) formats.

        Args:
            content: Raw JSON string
            source_file: Optional source file path

        Returns:
            ScanImport with parsed data summary
        """
        self.findings = []
        self.hosts = []
        self.services = []
        self.vulnerabilities = []
        self.errors = []
        self._host_cache = {}
        self._service_cache = {}

        lines: list[str] = content.strip().split("\n")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            try:
                finding: dict[str, Any] = json.loads(line)
                self._process_finding(finding)

            except json.JSONDecodeError as e:
                self.errors.append(f"Line {line_num}: JSON parse error - {e}")

        scan_import: ScanImport = ScanImport(
            source_type="nuclei",
            source_file=source_file,
            host_count=len(self.hosts),
            service_count=len(self.services),
            vulnerability_count=len(self.vulnerabilities),
            raw_data={
                "findings_count": len(self.findings),
                "template_count": len(set(
                    f.get("template-id", "") for f in self.findings
                )),
            },
        )

        return scan_import

    def _process_finding(self, finding: dict[str, Any]) -> None:
        """Process single Nuclei finding."""
        self.findings.append(finding)

        host: str = finding.get("host", "")
        ip: str = finding.get("ip", "")
        port: int = finding.get("port", 0)

        if not host and not ip:
            self.errors.append("Finding missing host and IP")
            return

        host_id: UUID = self._get_or_create_host(ip or host, finding)
        service_id: Optional[UUID] = None

        if port > 0:
            service_id = self._get_or_create_service(host_id, port, finding)

        self._create_vulnerability(finding, host_id, service_id)

    def _get_or_create_host(self, address: str, finding: dict[str, Any]) -> UUID:
        """Get existing host or create new one."""
        if address in self._host_cache:
            return self._host_cache[address]

        host_id: UUID = uuid4()

        hostname: Optional[str] = None
        if address and not self._is_ip(address):
            hostname = address

        host: Host = Host(
            id=host_id,
            ip=address if self._is_ip(address) else finding.get("ip", address),
            hostname=hostname,
            metadata={
                "source": "nuclei",
                "template": finding.get("template-id", ""),
                "matcher": finding.get("matcher-name", ""),
                "parsed_at": datetime.utcnow().isoformat(),
            }
        )

        self.hosts.append(host)
        self._host_cache[address] = host_id

        return host_id

    def _get_or_create_service(
        self,
        host_id: UUID,
        port: int,
        finding: dict[str, Any]
    ) -> UUID:
        """Get existing service or create new one."""
        cache_key: str = f"{host_id}:{port}"
        if cache_key in self._service_cache:
            return self._service_cache[cache_key]

        service_id: UUID = uuid4()

        extracted: Optional[dict[str, Any]] = finding.get("extracted-results")
        banner: Optional[str] = None
        if extracted:
            banner = str(extracted)[:200]

        service: Service = Service(
            id=service_id,
            host_id=host_id,
            port=port,
            protocol="tcp",
            name=finding.get("matcher-name"),
            banner=banner,
            state="open",
            metadata={
                "source": "nuclei",
                "template": finding.get("template-id", ""),
                "parsed_at": datetime.utcnow().isoformat(),
            }
        )

        self.services.append(service)
        self._service_cache[cache_key] = service_id

        return service_id

    def _create_vulnerability(
        self,
        finding: dict[str, Any],
        host_id: UUID,
        service_id: Optional[UUID]
    ) -> None:
        """Create vulnerability from finding."""
        template_id: str = finding.get("template-id", "unknown")
        info: dict[str, Any] = finding.get("info", {})

        severity: str = info.get("severity", "unknown").lower()
        cvss_score: Optional[float] = None

        severity_map: dict[str, float] = {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        cvss_score = severity_map.get(severity)

        cve_ids: list[str] = []
        classification: dict[str, Any] = info.get("classification", {})
        cve_id_list: list[str] = classification.get("cve-id", [])
        if isinstance(cve_id_list, list):
            cve_ids = cve_id_list
        elif isinstance(cve_id_list, str):
            cve_ids = [cve_id_list]

        primary_cve: Optional[str] = cve_ids[0] if cve_ids else None

        cwe_id_list: list[str] = classification.get("cwe-id", [])
        cwe_id: Optional[str] = None
        if isinstance(cwe_id_list, list) and cwe_id_list:
            cwe_id = cwe_id_list[0]
        elif isinstance(cwe_id_list, str):
            cwe_id = cwe_id_list

        references: list[str] = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        tags: list[str] = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
        if template_id.startswith("cve"):
            maturity = ExploitMaturity.FUNCTIONAL

        vuln: Vulnerability = Vulnerability(
            id=uuid4(),
            cve_id=primary_cve,
            service_id=service_id,
            host_id=host_id if service_id is None else None,
            title=info.get("name", template_id),
            description=info.get("description"),
            cvss_score=cvss_score,
            exploit_maturity=maturity,
            cwe_id=cwe_id,
            references=references,
            tags=tags,
            metadata={
                "source": "nuclei",
                "template": template_id,
                "severity": severity,
                "matcher": finding.get("matcher-name", ""),
                "curl_command": finding.get("curl-command"),
                "request": finding.get("request"),
                "response": finding.get("response"),
                "parsed_at": datetime.utcnow().isoformat(),
            }
        )

        self.vulnerabilities.append(vuln)

    def _is_ip(self, address: str) -> bool:
        """Check if address is IP (IPv4 or IPv6)."""
        import re
        ipv4_pattern: str = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        return bool(re.match(ipv4_pattern, address))

    def get_hosts(self) -> list[Host]:
        """Return parsed hosts."""
        return self.hosts

    def get_services(self) -> list[Service]:
        """Return parsed services."""
        return self.services

    def get_vulnerabilities(self) -> list[Vulnerability]:
        """Return parsed vulnerabilities."""
        return self.vulnerabilities

    def get_errors(self) -> list[str]:
        """Return parsing errors."""
        return self.errors

    def to_dict(self) -> dict[str, Any]:
        """Export parsed data as dictionary."""
        return {
            "findings": self.findings,
            "hosts": [h.model_dump() for h in self.hosts],
            "services": [s.model_dump() for s in self.services],
            "vulnerabilities": [v.model_dump() for v in self.vulnerabilities],
            "errors": self.errors,
            "summary": {
                "finding_count": len(self.findings),
                "host_count": len(self.hosts),
                "service_count": len(self.services),
                "vulnerability_count": len(self.vulnerabilities),
                "error_count": len(self.errors),
            }
        }
