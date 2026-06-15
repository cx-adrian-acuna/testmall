"""
Comprehensive tests for XSS remediation in the admin dashboard
Tests the role_badge filter to ensure proper escaping of untrusted data
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template_string
from models import db, User
from utils.jinja_filters import role_badge


class TestRoleBadgeXSSProtection:
    """Test XSS protection in role_badge filter"""

    def test_role_badge_escapes_script_tags(self, app):
        """Test that script tags in role field are properly escaped"""
        with app.app_context():
            # Simulate malicious role with script tag
            malicious_role = '<script>alert("XSS")</script>'
            result = role_badge(None, malicious_role)

            # Verify script tags are escaped
            assert '<script>' not in result
            assert '&lt;script&gt;' in result
            assert 'alert' not in result or '&lt;script&gt;alert' in result

    def test_role_badge_escapes_html_injection(self, app):
        """Test that HTML injection attempts are escaped"""
        with app.app_context():
            # Simulate role with HTML injection attempt
            malicious_role = 'admin"><img src=x onerror=alert(1)>'
            result = role_badge(None, malicious_role)

            # Verify HTML is escaped
            assert 'onerror=' not in result
            assert '&gt;' in result or '&quot;' in result
            # Ensure the malicious payload doesn't get executed
            assert '<img' not in result

    def test_role_badge_escapes_event_handlers(self, app):
        """Test that event handlers are escaped"""
        with app.app_context():
            # Simulate role with event handler
            malicious_role = 'admin" onload="alert(1)'
            result = role_badge(None, malicious_role)

            # Verify event handler is escaped
            assert 'onload=' not in result
            assert '&quot;' in result

    def test_role_badge_escapes_javascript_protocol(self, app):
        """Test that javascript: protocol is escaped"""
        with app.app_context():
            # Simulate role with javascript protocol
            malicious_role = 'admin"><a href="javascript:alert(1)">click</a>'
            result = role_badge(None, malicious_role)

            # Verify javascript protocol is escaped
            assert 'javascript:' not in result
            assert '&lt;' in result or '&gt;' in result

    def test_role_badge_valid_roles_work_correctly(self, app):
        """Test that legitimate role values work correctly"""
        with app.app_context():
            # Test valid roles
            valid_roles = ['admin', 'project_manager', 'team_member']

            for role in valid_roles:
                result = role_badge(None, role)

                # Verify the role is present in output
                assert role in result
                # Verify proper HTML structure
                assert '<span class="badge' in result
                assert '</span>' in result
                # Ensure no escaping for valid values
                assert '&lt;' not in result
                assert '&gt;' not in result

    def test_role_badge_correct_css_classes(self, app):
        """Test that correct CSS classes are applied for each role"""
        with app.app_context():
            # Test admin role
            admin_result = role_badge(None, 'admin')
            assert 'badge-danger' in admin_result

            # Test project_manager role
            pm_result = role_badge(None, 'project_manager')
            assert 'badge-primary' in pm_result

            # Test team_member role
            tm_result = role_badge(None, 'team_member')
            assert 'badge-secondary' in tm_result

            # Test unknown role (should default to secondary)
            unknown_result = role_badge(None, 'unknown_role')
            assert 'badge-secondary' in unknown_result

    def test_role_badge_handles_special_characters(self, app):
        """Test that special characters are properly escaped"""
        with app.app_context():
            # Test various special characters
            special_chars = [
                '<>&"\'',
                '<<>>&&""',
                '<img src=x>',
                '"><script>',
            ]

            for chars in special_chars:
                result = role_badge(None, chars)

                # Verify special chars are escaped
                assert '<' not in result or '&lt;' in result
                assert '>' not in result or '&gt;' in result

    def test_role_badge_prevents_attribute_injection(self, app):
        """Test that attribute injection is prevented"""
        with app.app_context():
            # Simulate role with attribute injection
            malicious_role = 'admin" style="display:none" data-x="'
            result = role_badge(None, malicious_role)

            # Verify attributes are escaped
            assert 'style=' not in result or '&quot;' in result
            assert 'data-x=' not in result or '&quot;' in result


class TestAdminDashboardXSSProtection:
    """Test XSS protection in admin dashboard endpoint"""

    def test_admin_dashboard_renders_safely_with_malicious_role(self, app, client, db_session):
        """Test that admin dashboard renders safely even with malicious role in database"""
        with app.app_context():
            # Create user with malicious role
            malicious_user = User(
                username='attacker',
                email='attacker@example.com',
                role='<script>alert("XSS")</script>'
            )
            malicious_user.set_password('password123')
            db_session.add(malicious_user)
            db_session.commit()

            # Register the admin route
            from utils.jinja_filters import (
                format_datetime, user_display_name, truncate,
                md5_hash, request_id_filter, format_file_size, role_badge
            )
            app.jinja_env.filters['format_datetime'] = format_datetime
            app.jinja_env.filters['user_display_name'] = user_display_name
            app.jinja_env.filters['truncate'] = truncate
            app.jinja_env.filters['md5_hash'] = md5_hash
            app.jinja_env.filters['request_id_filter'] = request_id_filter
            app.jinja_env.filters['format_file_size'] = format_file_size
            app.jinja_env.filters['role_badge'] = role_badge

            # Import and register the admin route
            from app import admin_dashboard
            app.add_url_rule('/admin', 'admin_dashboard', admin_dashboard)

            # Request the admin dashboard
            response = client.get('/admin')

            # Verify response
            assert response.status_code == 200
            response_data = response.data.decode('utf-8')

            # Verify script tag is escaped in the response
            assert '<script>alert("XSS")</script>' not in response_data
            assert '&lt;script&gt;' in response_data or 'alert' not in response_data

    def test_admin_dashboard_handles_multiple_xss_attempts(self, app, client, db_session):
        """Test that admin dashboard handles multiple users with XSS attempts"""
        with app.app_context():
            # Create multiple users with different XSS payloads
            xss_payloads = [
                '<script>alert(1)</script>',
                'admin"><img src=x onerror=alert(2)>',
                'test" onload="alert(3)',
                '<iframe src="javascript:alert(4)">',
            ]

            for i, payload in enumerate(xss_payloads):
                user = User(
                    username=f'attacker{i}',
                    email=f'attacker{i}@example.com',
                    role=payload
                )
                user.set_password('password123')
                db_session.add(user)

            db_session.commit()

            # Register filters and route
            from utils.jinja_filters import (
                format_datetime, user_display_name, truncate,
                md5_hash, request_id_filter, format_file_size, role_badge
            )
            app.jinja_env.filters['format_datetime'] = format_datetime
            app.jinja_env.filters['user_display_name'] = user_display_name
            app.jinja_env.filters['truncate'] = truncate
            app.jinja_env.filters['md5_hash'] = md5_hash
            app.jinja_env.filters['request_id_filter'] = request_id_filter
            app.jinja_env.filters['format_file_size'] = format_file_size
            app.jinja_env.filters['role_badge'] = role_badge

            from app import admin_dashboard
            app.add_url_rule('/admin', 'admin_dashboard', admin_dashboard)

            # Request the admin dashboard
            response = client.get('/admin')

            # Verify response
            assert response.status_code == 200
            response_data = response.data.decode('utf-8')

            # Verify all XSS payloads are escaped
            for payload in xss_payloads:
                # The raw payload should not be present
                assert payload not in response_data

            # Verify dangerous patterns are not present
            assert 'onerror=' not in response_data
            assert 'onload=' not in response_data
            assert 'javascript:' not in response_data

    def test_admin_dashboard_preserves_legitimate_roles(self, app, client, db_session):
        """Test that legitimate roles are displayed correctly"""
        with app.app_context():
            # Create users with legitimate roles
            legitimate_roles = ['admin', 'project_manager', 'team_member']

            for role in legitimate_roles:
                user = User(
                    username=f'user_{role}',
                    email=f'{role}@example.com',
                    role=role
                )
                user.set_password('password123')
                db_session.add(user)

            db_session.commit()

            # Register filters and route
            from utils.jinja_filters import (
                format_datetime, user_display_name, truncate,
                md5_hash, request_id_filter, format_file_size, role_badge
            )
            app.jinja_env.filters['format_datetime'] = format_datetime
            app.jinja_env.filters['user_display_name'] = user_display_name
            app.jinja_env.filters['truncate'] = truncate
            app.jinja_env.filters['md5_hash'] = md5_hash
            app.jinja_env.filters['request_id_filter'] = request_id_filter
            app.jinja_env.filters['format_file_size'] = format_file_size
            app.jinja_env.filters['role_badge'] = role_badge

            from app import admin_dashboard
            app.add_url_rule('/admin', 'admin_dashboard', admin_dashboard)

            # Request the admin dashboard
            response = client.get('/admin')

            # Verify response
            assert response.status_code == 200
            response_data = response.data.decode('utf-8')

            # Verify legitimate roles are present
            for role in legitimate_roles:
                assert role in response_data

            # Verify proper badge structure
            assert 'badge-danger' in response_data  # for admin
            assert 'badge-primary' in response_data  # for project_manager
            assert 'badge-secondary' in response_data  # for team_member


class TestMarkupSafeIntegration:
    """Test that MarkupSafe escape function works correctly"""

    def test_markupsafe_import(self):
        """Test that MarkupSafe can be imported"""
        from markupsafe import escape
        assert escape is not None

    def test_markupsafe_escapes_html(self):
        """Test basic HTML escaping with MarkupSafe"""
        from markupsafe import escape

        # Test basic HTML characters
        assert str(escape('<')) == '&lt;'
        assert str(escape('>')) == '&gt;'
        assert str(escape('&')) == '&amp;'
        assert str(escape('"')) == '&#34;'
        assert str(escape("'")) == '&#39;'

    def test_markupsafe_escapes_complete_tag(self):
        """Test that complete HTML tags are escaped"""
        from markupsafe import escape

        malicious = '<script>alert("XSS")</script>'
        escaped = str(escape(malicious))

        # Verify script tag is fully escaped
        assert '<script>' not in escaped
        assert '&lt;script&gt;' in escaped
        assert '</script>' not in escaped


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
