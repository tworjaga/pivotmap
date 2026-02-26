"""
Nmap XML parser for scan result ingestion.

Extracts host, service, and OS information from Nmap XML output.
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID, uuid4

from pivotmap.core.models import Host, ScanImport, Service


class NmapParser:
    """
    Parse Nmap XML scan results.

    Handles standard Nmap XML format with host, port, and service details.
    """

    def __init__(self) -> None:
        """Initialize parser state."""
        self.scan_metadata: dict[str, Any] = {}
        self.hosts: list[Host] = []
        self.services: list[Service] = []
        self.errors: list[str] = []

    def parse_file(self, file_path: str | Path) -> ScanImport:
        """
        Parse Nmap XML file and return import metadata.

        Args:
            file_path: Path to Nmap XML file

        Returns:
            ScanImport with parsed data summary
        """
        path: Path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found: {file_path}")

        try:
            tree: ET.ElementTree = ET.parse(path)
            root: ET.Element = tree.getroot()

            return self._parse_root(root, str(path))

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {e}")

    def parse_string(self, xml_content: str) -> ScanImport:
        """
        Parse Nmap XML from string content.

        Args:
            xml_content: Raw XML string

        Returns:
            ScanImport with parsed data summary
        """
        try:
            root: ET.Element = ET.fromstring(xml_content)
            return self._parse_root(root, None)

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {e}")

    def _parse_root(self, root: ET.Element, source_file: Optional[str]) -> ScanImport:
        """Parse Nmap XML root element."""
        if root.tag != "nmaprun":
            raise ValueError("Invalid Nmap XML: root element must be 'nmaprun'")

        self.scan_metadata = {
            "scanner": root.get("scanner", "nmap"),
            "version": root.get("version", "unknown"),
            "start_time": root.get("start", ""),
            "args": root.get("args", ""),
        }

        self.hosts = []
        self.services = []
        self.errors = []

        for host_elem in root.findall("host"):
            try:
                host, host_services = self._parse_host(host_elem)
                self.hosts.append(host)
                self.services.extend(host_services)

            except Exception as e:
                self.errors.append(f"Failed to parse host: {e}")

        scan_import: ScanImport = ScanImport(
            source_type="nmap",
            source_file=source_file,
            host_count=len(self.hosts),
            service_count=len(self.services),
            vulnerability_count=0,
            raw_data=self.scan_metadata,
        )

        return scan_import

    def _parse_host(self, host_elem: ET.Element) -> tuple[Host, list[Service]]:
        """Parse individual host element."""
        address_elem: Optional[ET.Element] = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address")

        ip: str = address_elem.get("addr", "0.0.0.0") if address_elem is not None else "0.0.0.0"

        mac_elem: Optional[ET.Element] = host_elem.find("address[@addrtype='mac']")
        mac: Optional[str] = mac_elem.get("addr") if mac_elem is not None else None

        hostname: Optional[str] = None
        hostnames_elem: Optional[ET.Element] = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem: Optional[ET.Element] = hostnames_elem.find("hostname[@type='PTR']")
            if hostname_elem is None:
                hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")

        os: Optional[str] = None
        os_elem: Optional[ET.Element] = host_elem.find("os/osmatch")
        if os_elem is not None:
            os = os_elem.get("name")

        host: Host = Host(
            id=uuid4(),
            ip=ip,
            hostname=hostname,
            mac=mac,
            os=os,
            metadata={
                "source": "nmap",
                "parsed_at": datetime.utcnow().isoformat(),
            }
        )

        services: list[Service] = []
        ports_elem: Optional[ET.Element] = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                try:
                    service: Service = self._parse_port(port_elem, host.id)
                    services.append(service)
                except Exception as e:
                    self.errors.append(f"Failed to parse port: {e}")

        return host, services

    def _parse_port(self, port_elem: ET.Element, host_id: UUID) -> Service:
        """Parse port/service element."""
        portid: str = port_elem.get("portid", "0")
        protocol: str = port_elem.get("protocol", "tcp")

        try:
            port: int = int(portid)
        except ValueError:
            port = 0

        state: str = "unknown"
        state_elem: Optional[ET.Element] = port_elem.find("state")
        if state_elem is not None:
            state = state_elem.get("state", "unknown")

        name: Optional[str] = None
        version: Optional[str] = None
        banner: Optional[str] = None

        service_elem: Optional[ET.Element] = port_elem.find("service")
        if service_elem is not None:
            name = service_elem.get("name")
            version = service_elem.get("version")
            product: Optional[str] = service_elem.get("product")

            if product:
                banner = product
                if version:
                    banner = f"{product} {version}"

        service: Service = Service(
            id=uuid4(),
            host_id=host_id,
            port=port,
            protocol=protocol,
            name=name,
            version=version,
            banner=banner,
            state=state if state in ["open", "closed", "filtered"] else "unknown",
            metadata={
                "source": "nmap",
                "parsed_at": datetime.utcnow().isoformat(),
            }
        )

        return service

    def get_hosts(self) -> list[Host]:
        """Return parsed hosts."""
        return self.hosts

    def get_services(self) -> list[Service]:
        """Return parsed services."""
        return self.services

    def get_errors(self) -> list[str]:
        """Return parsing errors."""
        return self.errors

    def to_dict(self) -> dict[str, Any]:
        """Export parsed data as dictionary."""
        return {
            "metadata": self.scan_metadata,
            "hosts": [h.model_dump() for h in self.hosts],
            "services": [s.model_dump() for s in self.services],
            "errors": self.errors,
            "summary": {
                "host_count": len(self.hosts),
                "service_count": len(self.services),
                "error_count": len(self.errors),
            }
        }
