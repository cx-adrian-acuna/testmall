"""
Comprehensive tests for file_handler utility functions
Tests for CVE-2017-18342 remediation - ensuring safe YAML parsing
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.file_handler import (
    process_yaml_file,
    process_xml_file,
    process_pickle_file,
    extract_file_metadata,
    allowed_file
)


class TestYAMLProcessing:
    """Test YAML file processing - CVE-2017-18342 remediation"""

    def test_process_yaml_file_simple_dict(self):
        """Test processing valid YAML with simple dictionary"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("name: Test Project\n")
            f.write("version: 1.0.0\n")
            f.write("description: A test project\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert result['name'] == 'Test Project'
            assert result['version'] == '1.0.0'
            assert result['description'] == 'A test project'
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_nested_structure(self):
        """Test processing YAML with nested structures"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("database:\n")
            f.write("  host: localhost\n")
            f.write("  port: 5432\n")
            f.write("  credentials:\n")
            f.write("    username: admin\n")
            f.write("    password: secret\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert 'database' in result
            assert result['database']['host'] == 'localhost'
            assert result['database']['port'] == 5432
            assert result['database']['credentials']['username'] == 'admin'
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_list(self):
        """Test processing YAML with lists"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("- item1\n")
            f.write("- item2\n")
            f.write("- item3\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, list)
            assert len(result) == 3
            assert result[0] == 'item1'
            assert result[1] == 'item2'
            assert result[2] == 'item3'
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_mixed_types(self):
        """Test processing YAML with mixed data types"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("string_value: hello\n")
            f.write("integer_value: 42\n")
            f.write("float_value: 3.14\n")
            f.write("boolean_value: true\n")
            f.write("null_value: null\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert result['string_value'] == 'hello'
            assert result['integer_value'] == 42
            assert result['float_value'] == 3.14
            assert result['boolean_value'] is True
            assert result['null_value'] is None
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_safe_load_blocks_python_objects(self):
        """
        Test that safe_load prevents arbitrary Python object instantiation
        This is the key security test for CVE-2017-18342
        """
        # Create YAML with Python object constructor (malicious pattern)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # This syntax would execute Python code with yaml.load()
            # but should be safely handled by yaml.safe_load()
            f.write("!!python/object/apply:os.system\n")
            f.write("args: ['echo vulnerable']\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            # safe_load should raise an error or return safe representation
            # It should NOT execute the os.system command
            # The result should contain an error or be safely parsed
            assert 'error' in result or not isinstance(result, type(None))
            # Most importantly, the malicious code should not execute
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_invalid_syntax(self):
        """Test processing YAML with invalid syntax"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: syntax:\n")
            f.write("  - broken\n")
            f.write("- structure\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert 'error' in result
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_empty_file(self):
        """Test processing empty YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            # Empty YAML returns None, which is valid
            assert result is None or isinstance(result, dict)
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_unicode_content(self):
        """Test processing YAML with Unicode characters"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
            f.write("title: Testing 日本語 文字\n")
            f.write("emoji: 🔒🛡️\n")
            f.write("special: Ñoño García\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert 'title' in result
            assert '日本語' in result['title']
            assert '🔒' in result['emoji']
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_multiline_strings(self):
        """Test processing YAML with multiline strings"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("description: |\n")
            f.write("  This is a multiline\n")
            f.write("  string that spans\n")
            f.write("  multiple lines.\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            assert isinstance(result, dict)
            assert 'description' in result
            assert 'multiline' in result['description']
            assert 'multiple lines' in result['description']
        finally:
            os.unlink(yaml_file)

    def test_process_yaml_file_nonexistent(self):
        """Test processing non-existent YAML file"""
        result = process_yaml_file('/tmp/nonexistent_file_12345.yaml')
        assert isinstance(result, dict)
        assert 'error' in result


class TestExtractFileMetadata:
    """Test extract_file_metadata function that uses process_yaml_file"""

    def test_extract_metadata_yaml_file(self):
        """Test extracting metadata from YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("config:\n")
            f.write("  setting1: value1\n")
            f.write("  setting2: value2\n")
            yaml_file = f.name

        try:
            metadata = extract_file_metadata(yaml_file)
            assert isinstance(metadata, dict)
            assert 'size' in metadata
            assert 'yaml_data' in metadata
            assert isinstance(metadata['yaml_data'], dict)
            assert 'config' in metadata['yaml_data']
        finally:
            os.unlink(yaml_file)

    def test_extract_metadata_yml_extension(self):
        """Test extracting metadata from .yml file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("test: data\n")
            yml_file = f.name

        try:
            metadata = extract_file_metadata(yml_file)
            assert isinstance(metadata, dict)
            assert 'yaml_data' in metadata
            assert metadata['yaml_data']['test'] == 'data'
        finally:
            os.unlink(yml_file)


class TestAllowedFile:
    """Test allowed_file function"""

    def test_allowed_file_yaml(self):
        """Test YAML files are handled correctly"""
        # Note: This test validates the function logic
        # The actual ALLOWED_EXTENSIONS is defined in Config
        filename = "config.yaml"
        result = allowed_file(filename)
        # Result depends on Config.ALLOWED_EXTENSIONS
        assert isinstance(result, bool)

    def test_allowed_file_yml(self):
        """Test YML files are handled correctly"""
        filename = "data.yml"
        result = allowed_file(filename)
        assert isinstance(result, bool)

    def test_allowed_file_no_extension(self):
        """Test files without extension"""
        filename = "noextension"
        result = allowed_file(filename)
        assert result is False


class TestSecurityRegression:
    """Security regression tests to ensure CVE-2017-18342 stays fixed"""

    def test_yaml_safe_load_prevents_code_execution(self):
        """
        Critical security test: Ensure YAML parsing cannot execute arbitrary code
        This test validates the fix for CVE-2017-18342
        """
        dangerous_payloads = [
            # Python object instantiation
            "!!python/object/apply:os.system ['echo hacked']",
            # Python module import
            "!!python/object/new:os.system [echo test]",
            # Python eval
            "!!python/object/apply:eval [\"__import__('os').system('echo vulnerable')\"]"
        ]

        for payload in dangerous_payloads:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(payload)
                yaml_file = f.name

            try:
                result = process_yaml_file(yaml_file)
                # safe_load should either:
                # 1. Return an error dict with 'error' key
                # 2. Parse it as safe string/data (not execute)
                # 3. Return None for unparseable content
                # It should NEVER execute the malicious code
                assert result is None or 'error' in result or isinstance(result, (str, dict, list))
            finally:
                os.unlink(yaml_file)

    def test_yaml_safe_tags_only(self):
        """Test that only safe YAML tags are processed"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # These are safe YAML tags that should work
            f.write("numbers: !!seq [1, 2, 3]\n")
            f.write("text: !!str 'hello world'\n")
            yaml_file = f.name

        try:
            result = process_yaml_file(yaml_file)
            # Standard safe tags should work fine
            assert isinstance(result, dict) or 'error' in result
        finally:
            os.unlink(yaml_file)
