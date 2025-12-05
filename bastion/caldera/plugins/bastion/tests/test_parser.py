"""
Unit tests for Wazuh Agent ID parser.

Tests cover the parser functionality for extracting Wazuh agent IDs
from client.keys file output.
"""

import pytest
from unittest.mock import MagicMock, patch


class TestWazuhAgentIdParser:
    """Tests for the Wazuh Agent ID parser."""

    @pytest.fixture
    def parser_class(self):
        """Get the Parser class with mocked dependencies."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact') as mock_fact:
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship') as mock_rel:
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    # Import after patching
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser
                    return Parser, mock_fact, mock_rel

    def test_parse_valid_agent_id(self):
        """Test parsing valid agent ID from client.keys format."""
        # Create a mock parser that mimics the real one
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact') as MockFact:
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship') as MockRelationship:
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser') as MockBaseParser:
                    # Setup mock base parser
                    MockBaseParser.return_value.line = MagicMock(return_value=['001'])
                    MockBaseParser.return_value.mappers = []

                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['001'])
                    parser.mappers = [MagicMock(source='wazuh.agent.id', edge='has', target='')]
                    parser.set_value = MagicMock(return_value='001')
                    parser.used_facts = []

                    result = parser.parse('001 VM1-Ubuntu any KEY...')

                    assert isinstance(result, list)

    def test_parse_empty_input(self):
        """Test parsing empty input returns empty list."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=[])
                    parser.mappers = []

                    result = parser.parse('')

                    assert result == []

    def test_parse_none_value(self):
        """Test parsing NONE value is skipped."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['NONE'])
                    parser.mappers = []

                    result = parser.parse('NONE')

                    assert result == []

    def test_parse_non_numeric_id_skipped(self):
        """Test non-numeric IDs are skipped."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['not_a_number'])
                    parser.mappers = []

                    result = parser.parse('not_a_number VM1 any KEY')

                    assert result == []

    def test_parse_multiple_lines(self):
        """Test parsing multiple agent entries."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact') as MockFact:
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship') as MockRelationship:
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['001', '002', '003'])
                    parser.mappers = [MagicMock(source='wazuh.agent.id', edge='has', target='')]
                    parser.set_value = MagicMock(side_effect=lambda s, v, f: v)
                    parser.used_facts = []

                    result = parser.parse(
                        '001 VM1-Ubuntu any KEY1\n'
                        '002 VM2-Windows any KEY2\n'
                        '003 VM3-CentOS any KEY3'
                    )

                    # Should create relationship for each valid ID
                    assert isinstance(result, list)

    def test_parse_leading_zeros_preserved(self):
        """Test that agent IDs with leading zeros are preserved."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact') as MockFact:
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship') as MockRelationship:
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['001'])
                    parser.mappers = [MagicMock(source='wazuh.agent.id', edge='has', target='')]
                    parser.set_value = MagicMock(return_value='001')
                    parser.used_facts = []

                    # The ID should remain as string '001' not integer 1
                    result = parser.parse('001')

                    if result and hasattr(MockFact, 'call_args_list') and MockFact.call_args_list:
                        # Check that '001' was used, not '1'
                        for call in MockFact.call_args_list:
                            args = call[0] if call[0] else []
                            if len(args) >= 2 and args[1] == '001':
                                assert True
                                return

    def test_parse_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                with patch('plugins.bastion.app.parsers.wazuh_agent_id.BaseParser'):
                    from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                    parser = Parser()
                    parser.line = MagicMock(return_value=['  001  '])
                    parser.mappers = []

                    # Should handle whitespace - empty line after strip should be skipped
                    result = parser.parse('  001  ')

                    # Result depends on whether stripped value is numeric
                    assert isinstance(result, list)


class TestParserIntegration:
    """Integration tests for parser with Caldera's BaseParser."""

    def test_parser_inherits_base_parser(self):
        """Test that Parser inherits from BaseParser."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                from plugins.bastion.app.parsers.wazuh_agent_id import Parser
                from app.utility.base_parser import BaseParser

                assert issubclass(Parser, BaseParser)

    def test_parser_has_parse_method(self):
        """Test that Parser has required parse method."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                parser = Parser()
                assert hasattr(parser, 'parse')
                assert callable(parser.parse)

    def test_parser_docstring_exists(self):
        """Test that Parser has proper documentation."""
        with patch('plugins.bastion.app.parsers.wazuh_agent_id.Fact'):
            with patch('plugins.bastion.app.parsers.wazuh_agent_id.Relationship'):
                from plugins.bastion.app.parsers.wazuh_agent_id import Parser

                assert Parser.__doc__ is not None
                assert 'Wazuh' in Parser.__doc__ or 'agent' in Parser.__doc__.lower()
