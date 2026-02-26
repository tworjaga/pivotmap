"""
CVE database loader and manager.

Handles loading CVE data from JSON/SQLite sources with lazy loading support.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from pivotmap.core.models import ExploitMaturity


class CVELoader:
    """
    Load and query CVE database.

    Supports JSON and SQLite backends with lazy loading.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        """
        Initialize CVE loader.

        Args:
            db_path: Path to CVE database (JSON or SQLite)
        """
        self.db_path: Optional[Path] = Path(db_path) if db_path else None
        self._cache: dict[str, Any] = {}
        self._cache_limit: int = 10000
        self._sqlite_conn: Optional[sqlite3.Connection] = None

    def load_json(self, json_path: str) -> int:
        """
        Load CVE data from JSON file.

        Args:
            json_path: Path to JSON file

        Returns:
            Number of CVEs loaded
        """
        path: Path = Path(json_path)
        if not path.exists():
            raise FileNotFoundError(f"CVE JSON not found: {json_path}")

        with open(path, "r", encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)

        if isinstance(data, dict):
            self._cache.update(data)
        elif isinstance(data, list):
            for item in data:
                cve_id: Optional[str] = item.get("cve_id") or item.get("id")
                if cve_id:
                    self._cache[cve_id] = item

        self._enforce_cache_limit()
        return len(self._cache)

    def load_sqlite(self, sqlite_path: str) -> int:
        """
        Initialize SQLite connection for CVE queries.

        Args:
            sqlite_path: Path to SQLite database

        Returns:
            Count of CVEs in database
        """
        self.db_path = Path(sqlite_path)

        if not self.db_path.exists():
            raise FileNotFoundError(f"CVE SQLite DB not found: {sqlite_path}")

        self._sqlite_conn = sqlite3.connect(str(self.db_path))
        self._sqlite_conn.row_factory = sqlite3.Row

        cursor: sqlite3.Cursor = self._sqlite_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        count: int = cursor.fetchone()[0]

        return count

    def get_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """
        Retrieve CVE by ID.

        Checks cache first, then database if configured.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-1234)

        Returns:
            CVE data dictionary or None
        """
        if cve_id in self._cache:
            return self._cache[cve_id]

        if self._sqlite_conn:
            return self._query_sqlite(cve_id)

        return None

    def _query_sqlite(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Query CVE from SQLite database."""
        if not self._sqlite_conn:
            return None

        cursor: sqlite3.Cursor = self._sqlite_conn.cursor()
        cursor.execute(
            "SELECT * FROM cves WHERE cve_id = ?",
            (cve_id,)
        )
        row: Optional[sqlite3.Row] = cursor.fetchone()

        if not row:
            return None

        result: dict[str, Any] = dict(row)

        if "affected_products" in result and isinstance(result["affected_products"], str):
            try:
                result["affected_products"] = json.loads(result["affected_products"])
            except json.JSONDecodeError:
                result["affected_products"] = []

        self._cache[cve_id] = result
        self._enforce_cache_limit()

        return result

    def search_by_product(
        self,
        product: str,
        vendor: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """
        Search CVEs by affected product.

        Args:
            product: Product name
            vendor: Optional vendor name

        Returns:
            List of matching CVEs
        """
        results: list[dict[str, Any]] = []

        product_lower: str = product.lower()

        for cve_id, cve_data in self._cache.items():
            affected: list[dict[str, Any]] = cve_data.get("affected_products", [])

            for item in affected:
                item_product: str = item.get("product", "").lower()
                item_vendor: str = item.get("vendor", "").lower()

                if product_lower in item_product or item_product in product_lower:
                    if vendor is None or vendor.lower() in item_vendor:
                        results.append(cve_data)
                        break

        return results

    def search_by_cvss(
        self,
        min_score: float = 0.0,
        max_score: float = 10.0
    ) -> list[dict[str, Any]]:
        """
        Search CVEs by CVSS score range.

        Args:
            min_score: Minimum CVSS score
            max_score: Maximum CVSS score

        Returns:
            List of matching CVEs
        """
        results: list[dict[str, Any]] = []

        for cve_id, cve_data in self._cache.items():
            score: Optional[float] = cve_data.get("cvss_score")
            if score is not None and min_score <= score <= max_score:
                results.append(cve_data)

        return results

    def get_by_maturity(self, maturity: ExploitMaturity) -> list[dict[str, Any]]:
        """
        Get CVEs by exploit maturity level.

        Args:
            maturity: Exploit maturity level

        Returns:
            List of matching CVEs
        """
        results: list[dict[str, Any]] = []

        for cve_id, cve_data in self._cache.items():
            cve_maturity: str = cve_data.get("exploit_maturity", "not_defined")
            if cve_maturity == maturity.value:
                results.append(cve_data)

        return results

    def _enforce_cache_limit(self) -> None:
        """Enforce cache size limit with LRU eviction."""
        if len(self._cache) > self._cache_limit:
            excess: int = len(self._cache) - self._cache_limit
            for key in list(self._cache.keys())[:excess]:
                del self._cache[key]

    def get_statistics(self) -> dict[str, Any]:
        """Return loader statistics."""
        return {
            "cache_size": len(self._cache),
            "cache_limit": self._cache_limit,
            "has_sqlite": self._sqlite_conn is not None,
            "db_path": str(self.db_path) if self.db_path else None,
        }

    def close(self) -> None:
        """Close database connections."""
        if self._sqlite_conn:
            self._sqlite_conn.close()
            self._sqlite_conn = None
