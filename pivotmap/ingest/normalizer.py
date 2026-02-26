"""
Data normalizer for standardizing scan results.

Converts various scan formats to internal PivotMap models.
"""

from typing import Any
from uuid import UUID

from pivotmap.core.models import Host, Service, Vulnerability
from pivotmap.ingest.nmap import NmapParser
from pivotmap.ingest.nuclei import NucleiParser


class DataNormalizer:
    """
    Normalize scan data from multiple sources into unified format.
    """

    def __init__(self) -> None:
        """Initialize normalizer."""
        self.hosts: list[Host] = []
        self.services: list[Service] = []
        self.vulnerabilities: list[Vulnerability] = []
        self._host_index: dict[str, Host] = {}
        self._service_index: dict[str, Service] = {}

    def normalize_nmap(self, file_path: str) -> dict[str, Any]:
        """
        Normalize Nmap scan results.

        Args:
            file_path: Path to Nmap XML file

        Returns:
            Normalized data dictionary
        """
        parser: NmapParser = NmapParser()
        parser.parse_file(file_path)

        hosts: list[Host] = parser.get_hosts()
        services: list[Service] = parser.get_services()

        self._merge_hosts(hosts)
        self._merge_services(services)

        return {
            "source": "nmap",
            "hosts": [h.model_dump() for h in hosts],
            "services": [s.model_dump() for s in services],
            "host_count": len(hosts),
            "service_count": len(services),
        }

    def normalize_nuclei(self, file_path: str) -> dict[str, Any]:
        """
        Normalize Nuclei scan results.

        Args:
            file_path: Path to Nuclei JSON file

        Returns:
            Normalized data dictionary
        """
        parser: NucleiParser = NucleiParser()
        parser.parse_file(file_path)

        hosts: list[Host] = parser.get_hosts()
        services: list[Service] = parser.get_services()
        vulnerabilities: list[Vulnerability] = parser.get_vulnerabilities()

        self._merge_hosts(hosts)
        self._merge_services(services)
        self._merge_vulnerabilities(vulnerabilities)

        return {
            "source": "nuclei",
            "hosts": [h.model_dump() for h in hosts],
            "services": [s.model_dump() for s in services],
            "vulnerabilities": [v.model_dump() for v in vulnerabilities],
            "host_count": len(hosts),
            "service_count": len(services),
            "vulnerability_count": len(vulnerabilities),
        }

    def _merge_hosts(self, new_hosts: list[Host]) -> None:
        """Merge hosts, avoiding duplicates by IP."""
        for host in new_hosts:
            key: str = host.ip
            if key in self._host_index:
                existing: Host = self._host_index[key]

                if host.hostname and not existing.hostname:
                    existing.hostname = host.hostname
                if host.os and not existing.os:
                    existing.os = host.os
                if host.mac and not existing.mac:
                    existing.mac = host.mac

                existing.metadata.update(host.metadata)
            else:
                self._host_index[key] = host
                self.hosts.append(host)

    def _merge_services(self, new_services: list[Service]) -> None:
        """Merge services, avoiding duplicates by host:port."""
        for service in new_services:
            key: str = f"{service.host_id}:{service.port}"
            if key in self._service_index:
                existing: Service = self._service_index[key]

                if service.name and not existing.name:
                    existing.name = service.name
                if service.version and not existing.version:
                    existing.version = service.version
                if service.banner and not existing.banner:
                    existing.banner = service.banner

                existing.metadata.update(service.metadata)
            else:
                self._service_index[key] = service
                self.services.append(service)

    def _merge_vulnerabilities(self, new_vulns: list[Vulnerability]) -> None:
        """Merge vulnerabilities, allowing duplicates for now."""
        self.vulnerabilities.extend(new_vulns)

    def get_all_hosts(self) -> list[Host]:
        """Return all normalized hosts."""
        return self.hosts

    def get_all_services(self) -> list[Service]:
        """Return all normalized services."""
        return self.services

    def get_all_vulnerabilities(self) -> list[Vulnerability]:
        """Return all normalized vulnerabilities."""
        return self.vulnerabilities

    def get_services_by_host(self, host_id: UUID) -> list[Service]:
        """Get services for specific host."""
        return [s for s in self.services if s.host_id == host_id]

    def get_vulnerabilities_by_host(self, host_id: UUID) -> list[Vulnerability]:
        """Get vulnerabilities for specific host."""
        return [
            v for v in self.vulnerabilities
            if v.host_id == host_id or (
                v.service_id and self._get_service_host(v.service_id) == host_id
            )
        ]

    def _get_service_host(self, service_id: UUID) -> UUID | None:
        """Get host ID for a service."""
        for svc in self.services:
            if svc.id == service_id:
                return svc.host_id
        return None

    def to_dict(self) -> dict[str, Any]:
        """Export all normalized data."""
        return {
            "hosts": [h.model_dump() for h in self.hosts],
            "services": [s.model_dump() for s in self.services],
            "vulnerabilities": [v.model_dump() for v in self.vulnerabilities],
            "summary": {
                "total_hosts": len(self.hosts),
                "total_services": len(self.services),
                "total_vulnerabilities": len(self.vulnerabilities),
            }
        }

    def clear(self) -> None:
        """Clear all normalized data."""
        self.hosts = []
        self.services = []
        self.vulnerabilities = []
        self._host_index = {}
        self._service_index = {}
