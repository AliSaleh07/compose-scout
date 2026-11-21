"""Docker Compose YAML file loader with safe deserialization."""

import os
from typing import Dict, Any, Tuple
import yaml


class ParseError(Exception):
    """Raised when Compose file is malformed or unreadable."""
    pass


def load_compose_file(path: str) -> Tuple[Dict[str, Any], str]:
    """Safely loads and validates the root structure of a Docker Compose file."""
    if not os.path.exists(path):
        raise ParseError(f"Compose file not found at path: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as exc:
        raise ParseError(f"Failed to read file {path}: {str(exc)}")

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ParseError(f"YAML parsing error in {path}: {str(exc)}")

    if not isinstance(data, dict):
        raise ParseError(f"Invalid Compose structure in {path}: root must be a mapping/dictionary")

    services = data.get("services")
    if not services or not isinstance(services, dict):
        raise ParseError(f"Compose file {path} contains no valid 'services' section")

    return data, content
