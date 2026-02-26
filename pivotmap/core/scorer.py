"""
PivotScore calculation engine.

Implements the scoring algorithm:
pivot_score = exploitability * exposure * privilege_gain * network_position * service_criticality
"""

from typing import Optional

from pivotmap.core.models import (
    ExploitMaturity,
    ExposureLevel,
    PrivilegeLevel,
    Service,
    Vulnerability,
)


class PivotScorer:
    """
    Calculates PivotScore for vulnerabilities and attack paths.

    Each factor normalized 0-1. Final score is product of all factors.
    """

    # Maturity weights based on exploit availability
    MATURITY_WEIGHTS: dict[ExploitMaturity, float] = {
        ExploitMaturity.UNPROVEN: 0.1,
        ExploitMaturity.PROOF_OF_CONCEPT: 0.4,
        ExploitMaturity.FUNCTIONAL: 0.7,
        ExploitMaturity.HIGH: 0.95,
        ExploitMaturity.NOT_DEFINED: 0.5,
    }

    # Exposure weights based on network position
    EXPOSURE_WEIGHTS: dict[ExposureLevel, float] = {
        ExposureLevel.EXTERNAL: 1.0,
        ExposureLevel.DMZ: 0.8,
        ExposureLevel.INTERNAL: 0.5,
        ExposureLevel.RESTRICTED: 0.2,
    }

    # Privilege escalation weights
    PRIVILEGE_WEIGHTS: dict[PrivilegeLevel, float] = {
        PrivilegeLevel.NONE: 0.1,
        PrivilegeLevel.USER: 0.4,
        PrivilegeLevel.ADMIN: 0.8,
        PrivilegeLevel.SYSTEM: 1.0,
    }

    # Service criticality by common port
    CRITICAL_PORTS: dict[int, float] = {
        22: 0.9,    # SSH
        23: 0.95,   # Telnet
        25: 0.7,    # SMTP
        53: 0.8,    # DNS
        80: 0.6,    # HTTP
        443: 0.7,   # HTTPS
        445: 0.95,  # SMB
        3389: 0.9,  # RDP
        3306: 0.85, # MySQL
        5432: 0.85, # PostgreSQL
        6379: 0.8,  # Redis
        8080: 0.5,  # HTTP Alt
        8443: 0.6,  # HTTPS Alt
    }

    DEFAULT_CRITICALITY: float = 0.5

    def __init__(self) -> None:
        """Initialize scorer with default weights."""
        pass

    def calculate_exploitability(self, vulnerability: Vulnerability) -> float:
        """
        Calculate exploitability factor from 0 to 1.

        Based on CVSS score and exploit maturity.
        """
        cvss_factor: float = 0.0

        if vulnerability.cvss_score is not None:
            cvss_factor = vulnerability.cvss_score / 10.0
        else:
            cvss_factor = 0.5

        maturity_factor: float = self.MATURITY_WEIGHTS.get(
            vulnerability.exploit_maturity,
            0.5
        )

        return (cvss_factor * 0.6) + (maturity_factor * 0.4)

    def calculate_exposure(self, exposure: ExposureLevel) -> float:
        """Calculate exposure factor from network position."""
        return self.EXPOSURE_WEIGHTS.get(exposure, 0.5)

    def calculate_privilege_gain(
        self,
        current: PrivilegeLevel,
        target: Optional[PrivilegeLevel] = None
    ) -> float:
        """
        Calculate privilege gain factor.

        If target specified, calculates escalation value.
        Otherwise returns current level weight.
        """
        current_weight: float = self.PRIVILEGE_WEIGHTS.get(current, 0.1)

        if target is None:
            return current_weight

        target_weight: float = self.PRIVILEGE_WEIGHTS.get(target, 0.1)

        if target_weight <= current_weight:
            return 0.1

        gain: float = target_weight - current_weight
        return min(gain, 1.0)

    def calculate_service_criticality(self, service: Service) -> float:
        """Calculate service criticality based on port and protocol."""
        base_criticality: float = self.CRITICAL_PORTS.get(
            service.port,
            self.DEFAULT_CRITICALITY
        )

        if service.protocol == "udp":
            base_criticality *= 0.9

        if service.name:
            name_lower: str = service.name.lower()
            if any(x in name_lower for x in ["admin", "mgmt", "manage"]):
                base_criticality = min(base_criticality * 1.2, 1.0)
            elif any(x in name_lower for x in ["backup", "db", "database"]):
                base_criticality = min(base_criticality * 1.15, 1.0)

        return base_criticality

    def calculate_network_position_weight(
        self,
        hop_count: int,
        is_segment_boundary: bool = False
    ) -> float:
        """
        Calculate network position weight.

        Closer to entry point = higher weight.
        Segment boundaries have elevated weight.
        """
        base_weight: float = max(0.1, 1.0 - (hop_count * 0.1))

        if is_segment_boundary:
            base_weight = min(base_weight * 1.3, 1.0)

        return base_weight

    def score_vulnerability(
        self,
        vulnerability: Vulnerability,
        service: Optional[Service] = None,
        exposure: ExposureLevel = ExposureLevel.INTERNAL
    ) -> float:
        """
        Calculate complete PivotScore for a vulnerability.

        Returns score between 0 and 1.
        """
        exploitability: float = self.calculate_exploitability(vulnerability)
        exposure_factor: float = self.calculate_exposure(exposure)

        privilege_factor: float = self.PRIVILEGE_WEIGHTS.get(
            PrivilegeLevel.NONE,
            0.1
        )

        if service:
            service_criticality: float = self.calculate_service_criticality(service)
            network_position: float = self.calculate_network_position_weight(0)
        else:
            service_criticality = self.DEFAULT_CRITICALITY
            network_position = 0.5

        pivot_score: float = (
            exploitability *
            exposure_factor *
            privilege_factor *
            network_position *
            service_criticality
        )

        return round(min(pivot_score, 1.0), 4)

    def score_attack_path(
        self,
        vulnerabilities: list[Vulnerability],
        services: list[Service],
        exposures: list[ExposureLevel],
        hop_count: int
    ) -> float:
        """
        Calculate aggregate score for an attack path.

        Considers cumulative vulnerability scores and path complexity.
        """
        if not vulnerabilities:
            return 0.0

        individual_scores: list[float] = []

        for i, vuln in enumerate(vulnerabilities):
            svc: Optional[Service] = services[i] if i < len(services) else None
            exp: ExposureLevel = exposures[i] if i < len(exposures) else ExposureLevel.INTERNAL

            score: float = self.score_vulnerability(vuln, svc, exp)
            individual_scores.append(score)

        if not individual_scores:
            return 0.0

        avg_vuln_score: float = sum(individual_scores) / len(individual_scores)
        max_vuln_score: float = max(individual_scores)

        complexity_penalty: float = max(0.1, 1.0 - (hop_count * 0.05))

        path_score: float = (max_vuln_score * 0.6 + avg_vuln_score * 0.4) * complexity_penalty

        return round(min(path_score, 1.0), 4)

    def explain_score(
        self,
        vulnerability: Vulnerability,
        service: Optional[Service] = None,
        exposure: ExposureLevel = ExposureLevel.INTERNAL
    ) -> dict[str, float]:
        """
        Provide score breakdown for explainability.

        Returns dictionary of factor values.
        """
        exploitability: float = self.calculate_exploitability(vulnerability)
        exposure_factor: float = self.calculate_exposure(exposure)
        privilege_factor: float = self.PRIVILEGE_WEIGHTS.get(PrivilegeLevel.NONE, 0.1)

        if service:
            service_criticality: float = self.calculate_service_criticality(service)
            network_position: float = self.calculate_network_position_weight(0)
        else:
            service_criticality = self.DEFAULT_CRITICALITY
            network_position = 0.5

        final_score: float = (
            exploitability *
            exposure_factor *
            privilege_factor *
            network_position *
            service_criticality
        )

        return {
            "exploitability": round(exploitability, 4),
            "exposure": round(exposure_factor, 4),
            "privilege_gain": round(privilege_factor, 4),
            "network_position": round(network_position, 4),
            "service_criticality": round(service_criticality, 4),
            "pivot_score": round(min(final_score, 1.0), 4),
        }
