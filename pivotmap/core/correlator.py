"""
Correlation engine for matching services to vulnerabilities.

Performs fuzzy version matching, CVE correlation, and false-positive filtering.
"""

import re
from typing import Any, Optional
from uuid import UUID

from pivotmap.core.models import ExploitMaturity, Service, Vulnerability


class VersionMatcher:
    """
    Fuzzy version matching for service-to-CVE correlation.
    """

    @staticmethod
    def normalize_version(version: Optional[str]) -> tuple[int, ...]:
        """
        Normalize version string to comparable tuple.

        Handles formats like:
        - 1.2.3
        - 2.0.1-beta
        - 1.2.3.4
        """
        if not version:
            return (0,)

        version_clean: str = version.split("-")[0].split("+")[0]
        version_clean = re.sub(r"[^0-9.]", "", version_clean)

        parts: list[str] = version_clean.split(".")
        numeric_parts: list[int] = []

        for part in parts:
            try:
                numeric_parts.append(int(part))
            except ValueError:
                break

        return tuple(numeric_parts) if numeric_parts else (0,)

    @staticmethod
    def version_in_range(
        version: str,
        affected_from: Optional[str] = None,
        affected_to: Optional[str] = None
    ) -> bool:
        """
        Check if version falls within affected range.
        """
        ver_tuple: tuple[int, ...] = VersionMatcher.normalize_version(version)

        if affected_from:
            from_tuple: tuple[int, ...] = VersionMatcher.normalize_version(affected_from)
            if ver_tuple < from_tuple:
                return False

        if affected_to:
            to_tuple: tuple[int, ...] = VersionMatcher.normalize_version(affected_to)
            if ver_tuple > to_tuple:
                return False

        return True

    @staticmethod
    def is_version_affected(
        service_version: str,
        affected_versions: list[str],
        unaffected_versions: Optional[list[str]] = None
    ) -> bool:
        """
        Check if service version matches affected version list.

        Supports exact match, prefix match, and range notation.
        """
        svc_ver: tuple[int, ...] = VersionMatcher.normalize_version(service_version)

        for affected in affected_versions:
            if affected.startswith(">="):
                min_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected[2:])
                if svc_ver >= min_ver:
                    return True
            elif affected.startswith(">"):
                min_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected[1:])
                if svc_ver > min_ver:
                    return True
            elif affected.startswith("<="):
                max_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected[2:])
                if svc_ver <= max_ver:
                    return True
            elif affected.startswith("<"):
                max_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected[1:])
                if svc_ver < max_ver:
                    return True
            elif affected.startswith("="):
                exact_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected[1:])
                if svc_ver == exact_ver:
                    return True
            else:
                affected_ver: tuple[int, ...] = VersionMatcher.normalize_version(affected)
                if svc_ver == affected_ver:
                    return True

        if unaffected_versions:
            for unaffected in unaffected_versions:
                unaffected_ver: tuple[int, ...] = VersionMatcher.normalize_version(unaffected)
                if svc_ver == unaffected_ver:
                    return False

        return False


class CorrelationEngine:
    """
    Main correlation engine for vulnerability matching.
    """

    def __init__(self, cve_database: Optional[dict[str, Any]] = None) -> None:
        """
        Initialize with optional CVE database.

        CVE database format:
        {
            "CVE-2021-1234": {
                "title": "...",
                "description": "...",
                "cvss_score": 7.5,
                "affected_products": [
                    {
                        "vendor": "apache",
                        "product": "httpd",
                        "versions": [">=2.4.0", "<2.4.48"]
                    }
                ],
                "exploit_maturity": "functional",
                "cwe_id": "CWE-78",
                "references": [...]
            }
        }
        """
        self.cve_db: dict[str, Any] = cve_database or {}
        self.version_matcher: VersionMatcher = VersionMatcher()
        self._false_positive_rules: list[dict[str, Any]] = []

    def load_cve_database(self, cve_data: dict[str, Any]) -> None:
        """Load or update CVE database."""
        self.cve_db.update(cve_data)

    def add_false_positive_rule(self, rule: dict[str, Any]) -> None:
        """
        Add false positive filtering rule.

        Rule format:
        {
            "cve_id": "CVE-2021-1234",
            "condition": {"port": 80, "service": "nginx"},
            "reason": "Nginx not affected"
        }
        """
        self._false_positive_rules.append(rule)

    def _check_false_positive(
        self,
        cve_id: str,
        service: Service
    ) -> tuple[bool, Optional[str]]:
        """
        Check if match is a known false positive.

        Returns (is_fp, reason).
        """
        for rule in self._false_positive_rules:
            if rule.get("cve_id") != cve_id:
                continue

            condition: dict[str, Any] = rule.get("condition", {})

            match: bool = True
            if "port" in condition and service.port != condition["port"]:
                match = False
            if "service" in condition:
                svc_name: Optional[str] = service.name
                if not svc_name or condition["service"].lower() not in svc_name.lower():
                    match = False

            if match:
                return True, rule.get("reason", "Known false positive")

        return False, None

    def _match_service_to_cve(
        self,
        service: Service,
        cve_entry: dict[str, Any]
    ) -> bool:
        """
        Check if service matches CVE affected products.
        """
        affected_products: list[dict[str, Any]] = cve_entry.get("affected_products", [])

        if not affected_products:
            return True

        service_name: Optional[str] = service.name
        if not service_name:
            return False

        service_name_lower: str = service_name.lower()

        for product in affected_products:
            product_name: str = product.get("product", "").lower()
            vendor: str = product.get("vendor", "").lower()

            name_match: bool = (
                product_name in service_name_lower or
                service_name_lower in product_name or
                vendor in service_name_lower
            )

            if not name_match:
                continue

            versions: list[str] = product.get("versions", [])
            if not versions:
                return True

            if service.version:
                if self.version_matcher.is_version_affected(service.version, versions):
                    return True
            else:
                return True

        return False

    def correlate_service(
        self,
        service: Service
    ) -> list[Vulnerability]:
        """
        Find all vulnerabilities affecting a service.

        Returns list of Vulnerability objects.
        """
        results: list[Vulnerability] = []

        for cve_id, cve_data in self.cve_db.items():
            if not self._match_service_to_cve(service, cve_data):
                continue

            is_fp, reason = self._check_false_positive(cve_id, service)
            if is_fp:
                continue

            maturity_str: str = cve_data.get("exploit_maturity", "not_defined")
            try:
                maturity: ExploitMaturity = ExploitMaturity(maturity_str)
            except ValueError:
                maturity = ExploitMaturity.NOT_DEFINED

            vuln: Vulnerability = Vulnerability(
                cve_id=cve_id,
                service_id=service.id,
                title=cve_data.get("title", "Unknown vulnerability"),
                description=cve_data.get("description"),
                cvss_score=cve_data.get("cvss_score"),
                cvss_vector=cve_data.get("cvss_vector"),
                exploit_maturity=maturity,
                cwe_id=cve_data.get("cwe_id"),
                references=cve_data.get("references", []),
                tags=cve_data.get("tags", []),
                metadata={
                    "correlation_confidence": 0.9,
                    "matched_service": service.name,
                    "matched_version": service.version,
                }
            )

            results.append(vuln)

        return results

    def correlate_bulk(
        self,
        services: list[Service]
    ) -> dict[UUID, list[Vulnerability]]:
        """
        Correlate multiple services in batch.

        Returns mapping of service_id -> vulnerabilities.
        """
        results: dict[UUID, list[Vulnerability]] = {}

        for service in services:
            vulns: list[Vulnerability] = self.correlate_service(service)
            if vulns:
                results[service.id] = vulns

        return results

    def enrich_vulnerability(self, vulnerability: Vulnerability) -> Vulnerability:
        """
        Enrich vulnerability with additional metadata from CVE database.
        """
        if not vulnerability.cve_id:
            return vulnerability

        cve_data: Optional[dict[str, Any]] = self.cve_db.get(vulnerability.cve_id)
        if not cve_data:
            return vulnerability

        if vulnerability.cvss_score is None:
            vulnerability.cvss_score = cve_data.get("cvss_score")

        if not vulnerability.description:
            vulnerability.description = cve_data.get("description")

        if not vulnerability.cwe_id:
            vulnerability.cwe_id = cve_data.get("cwe_id")

        if not vulnerability.references:
            vulnerability.references = cve_data.get("references", [])

        maturity_str: str = cve_data.get("exploit_maturity", "not_defined")
        if vulnerability.exploit_maturity == ExploitMaturity.NOT_DEFINED:
            try:
                vulnerability.exploit_maturity = ExploitMaturity(maturity_str)
            except ValueError:
                pass

        vulnerability.metadata["enriched"] = True
        vulnerability.metadata["enriched_at"] = "correlation_engine"

        return vulnerability

    def get_statistics(self) -> dict[str, Any]:
        """Return correlation engine statistics."""
        return {
            "cve_database_size": len(self.cve_db),
            "false_positive_rules": len(self._false_positive_rules),
        }
