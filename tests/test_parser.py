"""Tests for YAML loader and error handling."""

import os
import tempfile
import pytest
from compose_scout.parser import load_compose_file, ParseError


def test_load_valid_compose():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "hardened_compose.yaml")
    data, content = load_compose_file(path)
    assert "services" in data
    assert "secure_web" in data["services"]


def test_missing_file_raises_error():
    with pytest.raises(ParseError, match="not found"):
        load_compose_file("non_existent_file_path.yaml")


def test_invalid_yaml_raises_error():
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as tmp:
        tmp.write("services:\n  broken: [unclosed")
        tmp_path = tmp.name

    try:
        with pytest.raises(ParseError, match="YAML parsing error"):
            load_compose_file(tmp_path)
    finally:
        os.remove(tmp_path)
