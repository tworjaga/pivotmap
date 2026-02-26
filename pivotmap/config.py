"""
PivotMap configuration management.

Handles environment variables, config files, and runtime settings.
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    """Database connection settings."""
    url: str = Field(default="sqlite:///pivotmap.db")
    echo: bool = Field(default=False)
    pool_size: int = Field(default=5)
    max_overflow: int = Field(default=10)


class CVEConfig(BaseModel):
    """CVE database settings."""
    data_path: Path = Field(default=Path("./data/cve"))
    cache_enabled: bool = Field(default=True)
    cache_ttl_hours: int = Field(default=24)
    auto_update: bool = Field(default=False)


class GraphConfig(BaseModel):
    """Graph engine settings."""
    max_nodes: int = Field(default=10000)
    pruning_threshold: float = Field(default=0.1)
    enable_caching: bool = Field(default=True)
    cache_size: int = Field(default=1000)


class APIConfig(BaseModel):
    """API server settings."""
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    reload: bool = Field(default=False)
    workers: int = Field(default=1)


class PivotMapConfig(BaseModel):
    """
    Main PivotMap configuration.

    Loads from environment variables and config files.
    """
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cve: CVEConfig = Field(default_factory=CVEConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    api: APIConfig = Field(default_factory=APIConfig)

    @classmethod
    def from_file(cls, path: str) -> "PivotMapConfig":
        """
        Load configuration from YAML file.

        Args:
            path: Path to config file

        Returns:
            PivotMapConfig instance
        """
        config_path: Path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(config_path, "r") as f:
            data: dict[str, Any] = yaml.safe_load(f)

        return cls(**data)

    @classmethod
    def from_env(cls) -> "PivotMapConfig":
        """
        Load configuration from environment variables.

        Environment variables prefixed with PIVOTMAP_ are parsed.
        """
        config: PivotMapConfig = cls()

        # Debug mode
        if os.getenv("PIVOTMAP_DEBUG", "").lower() in ("true", "1", "yes"):
            config.debug = True

        # Log level
        if level := os.getenv("PIVOTMAP_LOG_LEVEL"):
            config.log_level = level

        # Database
        if db_url := os.getenv("PIVOTMAP_DATABASE_URL"):
            config.database.url = db_url

        # CVE data path
        if cve_path := os.getenv("PIVOTMAP_CVE_PATH"):
            config.cve.data_path = Path(cve_path)

        # API settings
        if api_host := os.getenv("PIVOTMAP_API_HOST"):
            config.api.host = api_host
        if api_port := os.getenv("PIVOTMAP_API_PORT"):
            config.api.port = int(api_port)

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.model_dump()

    def save(self, path: str) -> None:
        """
        Save configuration to YAML file.

        Args:
            path: Output file path
        """
        config_path: Path = Path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)


# Global config instance
_config: Optional[PivotMapConfig] = None


def get_config() -> PivotMapConfig:
    """
    Get or create global configuration instance.

    Returns:
        PivotMapConfig instance
    """
    global _config

    if _config is None:
        # Try to load from file first
        config_paths: list[str] = [
            "pivotmap.yaml",
            "pivotmap.yml",
            "config/pivotmap.yaml",
            os.path.expanduser("~/.pivotmap/config.yaml"),
        ]

        for path in config_paths:
            if Path(path).exists():
                _config = PivotMapConfig.from_file(path)
                break
        else:
            # Fall back to environment variables
            _config = PivotMapConfig.from_env()

    return _config


def set_config(config: PivotMapConfig) -> None:
    """
    Set global configuration instance.

    Args:
        config: Configuration to set
    """
    global _config
    _config = config


# Default configuration template
DEFAULT_CONFIG: str = """
# PivotMap Configuration

debug: false
log_level: INFO

database:
  url: sqlite:///pivotmap.db
  echo: false

cve:
  data_path: ./data/cve
  cache_enabled: true
  cache_ttl_hours: 24

graph:
  max_nodes: 10000
  pruning_threshold: 0.1
  enable_caching: true

api:
  host: 0.0.0.0
  port: 8000
  reload: false
"""
