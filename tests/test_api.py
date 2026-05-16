"""
Tests for the FastAPI endpoints.

Run with: pytest tests/ -v
"""

import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from app.main import app
from app.config import Settings, get_settings
from app.models import ReviewResponse, SecurityFinding, RiskLevel


# Create test client
client = TestClient(app)


def get_test_settings_with_auth():
    """Settings with auth token configured."""
    return Settings(
        api_auth_token="test-token",
        llm_api_key="fake-key"
    )


def get_test_settings_no_auth():
    """Settings without auth token."""
    return Settings(
        api_auth_token=None,
        llm_api_key="fake-key"
    )


# Sample diff for testing
SAMPLE_DIFF = """diff --git a/src/controllers/userController.js b/src/controllers/userController.js
index 1234567..abcdefg 100644
--- a/src/controllers/userController.js
+++ b/src/controllers/userController.js
@@ -45,6 +45,12 @@ async function getUser(req, res) {
   const userId = req.params.id;
-  const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
+  const query = `SELECT * FROM users WHERE id = ${userId}`;
+  const user = await db.query(query);
   res.json(user);
 }
"""

SAFE_DIFF = """diff --git a/README.md b/README.md
index 1234567..abcdefg 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,5 @@
 # My App
 
+This is a description of my app.
+
 Welcome to my application!
"""


class TestHealthEndpoint:
    """Tests for the health check endpoint."""
    
    def test_health_check_returns_200(self):
        """Health endpoint should return 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_health_check_returns_service_info(self):
        """Health endpoint should return service information."""
        response = client.get("/health")
        data = response.json()
        
        assert "status" in data
        assert "service" in data
        assert data["service"] == "AI AppSec PR Reviewer"
        assert "version" in data
        assert "llm_provider" in data


class TestRootEndpoint:
    """Tests for the root endpoint."""
    
    def test_root_returns_service_info(self):
        """Root endpoint should return service information."""
        response = client.get("/")
        assert response.status_code == 200
        
        data = response.json()
        assert "service" in data
        assert "docs" in data
        assert data["docs"] == "/docs"


class TestReviewPREndpoint:
    """Tests for the /review-pr endpoint."""
    
    def test_review_pr_requires_diff(self):
        """Request without diff should fail validation."""
        response = client.post("/review-pr", json={
            "repo": "org/repo",
            "pr_number": 1
        })
        assert response.status_code == 422  # Validation error
    
    def test_review_pr_requires_repo(self):
        """Request without repo should fail validation."""
        response = client.post("/review-pr", json={
            "pr_number": 1,
            "diff": SAMPLE_DIFF
        })
        assert response.status_code == 422
    
    def test_review_pr_requires_pr_number(self):
        """Request without pr_number should fail validation."""
        response = client.post("/review-pr", json={
            "repo": "org/repo",
            "diff": SAMPLE_DIFF
        })
        assert response.status_code == 422
    
    @patch("app.main.analyze_diff")
    def test_review_pr_returns_findings(self, mock_analyze):
        """Successful review should return findings."""
        # Mock the LLM response
        mock_analyze.return_value = ReviewResponse(
            summary="Found 1 high risk issue",
            findings=[
                SecurityFinding(
                    title="SQL Injection",
                    risk=RiskLevel.HIGH,
                    file="src/controllers/userController.js",
                    line_range="45-50",
                    description="User input concatenated into SQL query",
                    impact="Attacker can execute arbitrary SQL",
                    recommendation="Use parameterized queries",
                    example_fix="db.query('SELECT * FROM users WHERE id = ?', [userId])",
                    owasp="A03:2021 Injection",
                    cwe="CWE-89"
                )
            ],
            findings_markdown="## Security Review\n\nFound issues..."
        )
        
        response = client.post("/review-pr", json={
            "repo": "org/repo",
            "pr_number": 42,
            "language": "nodejs",
            "framework": "express",
            "diff": SAMPLE_DIFF
        })
        
        assert response.status_code == 200
        data = response.json()
        
        assert "summary" in data
        assert "findings" in data
        assert "findings_markdown" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["risk"] == "HIGH"
    
    @patch("app.main.analyze_diff")
    def test_review_pr_no_findings(self, mock_analyze):
        """Review with no issues should return empty findings."""
        mock_analyze.return_value = ReviewResponse(
            summary="No clear security vulnerabilities identified in this change.",
            findings=[],
            findings_markdown="## Security Review\n\nNo issues found."
        )
        
        response = client.post("/review-pr", json={
            "repo": "org/repo",
            "pr_number": 42,
            "diff": SAFE_DIFF
        })
        
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["findings"]) == 0
        assert "No clear security vulnerabilities" in data["summary"]


class TestAuthentication:
    """Tests for API authentication."""
    
    def test_auth_required_when_configured(self):
        """When auth token is configured, requests need valid token."""
        # Override the dependency to use settings with auth
        app.dependency_overrides[get_settings] = get_test_settings_with_auth
        
        try:
            # Request without token should fail with 401
            response = client.post("/review-pr", json={
                "repo": "org/repo",
                "pr_number": 1,
                "diff": SAMPLE_DIFF
            })
            assert response.status_code == 401
            
            # Request with wrong token should fail
            response = client.post(
                "/review-pr",
                json={
                    "repo": "org/repo",
                    "pr_number": 1,
                    "diff": SAMPLE_DIFF
                },
                headers={"Authorization": "Bearer wrong-token"}
            )
            assert response.status_code == 401
        finally:
            # Clean up the override
            app.dependency_overrides.clear()
    
    def test_auth_passes_with_valid_token(self):
        """Request with valid token should pass authentication."""
        app.dependency_overrides[get_settings] = get_test_settings_with_auth
        
        try:
            with patch("app.main.analyze_diff") as mock_analyze:
                mock_analyze.return_value = ReviewResponse(
                    summary="No issues found",
                    findings=[],
                    findings_markdown="## Security Review\n\nNo issues."
                )
                
                response = client.post(
                    "/review-pr",
                    json={
                        "repo": "org/repo",
                        "pr_number": 1,
                        "diff": SAMPLE_DIFF
                    },
                    headers={"Authorization": "Bearer test-token"}
                )
                # Should pass auth and return 200
                assert response.status_code == 200
        finally:
            app.dependency_overrides.clear()
    
    def test_auth_skipped_when_not_configured(self):
        """When no auth token is configured, requests should pass without token."""
        app.dependency_overrides[get_settings] = get_test_settings_no_auth
        
        try:
            with patch("app.main.analyze_diff") as mock_analyze:
                mock_analyze.return_value = ReviewResponse(
                    summary="No issues found",
                    findings=[],
                    findings_markdown="## Security Review\n\nNo issues."
                )
                
                # Request without token should pass when auth is not configured
                response = client.post("/review-pr", json={
                    "repo": "org/repo",
                    "pr_number": 1,
                    "diff": SAMPLE_DIFF
                })
                assert response.status_code == 200
        finally:
            app.dependency_overrides.clear()


class TestDiffParser:
    """Tests for diff parsing functionality."""
    
    def test_parse_simple_diff(self):
        """Test parsing a simple git diff."""
        from app.diff_parser import parse_diff
        
        parsed = parse_diff(SAMPLE_DIFF)
        
        assert parsed.file_count == 1
        assert parsed.files[0].path == "src/controllers/userController.js"
        assert len(parsed.files[0].hunks) >= 1
    
    def test_parse_empty_diff(self):
        """Test parsing an empty diff."""
        from app.diff_parser import parse_diff
        
        parsed = parse_diff("")
        
        assert parsed.file_count == 0
        assert len(parsed.files) == 0
    
    def test_security_relevant_files(self):
        """Test detection of security-relevant files."""
        from app.diff_parser import parse_diff
        
        parsed = parse_diff(SAMPLE_DIFF)
        relevant = parsed.get_security_relevant_files()
        
        # userController.js should be detected as security-relevant
        assert len(relevant) >= 1
        assert any("controller" in f.path.lower() for f in relevant)


class TestMarkdownGeneration:
    """Tests for markdown comment generation."""
    
    def test_markdown_with_findings(self):
        """Test markdown generation with findings."""
        from app.llm_client import _build_findings_markdown
        
        findings = [
            SecurityFinding(
                title="SQL Injection",
                risk=RiskLevel.HIGH,
                file="test.js",
                line_range="10-15",
                description="SQL injection vulnerability",
                impact="Data breach",
                recommendation="Use parameterized queries",
                owasp="A03:2021 Injection",
                cwe="CWE-89"
            )
        ]
        
        markdown = _build_findings_markdown("Found 1 issue", findings)
        
        assert "AI Security Review" in markdown
        assert "SQL Injection" in markdown
        assert "HIGH" in markdown
        assert "CWE-89" in markdown
    
    def test_markdown_without_findings(self):
        """Test markdown generation with no findings."""
        from app.llm_client import _build_findings_markdown
        
        markdown = _build_findings_markdown(
            "No clear security vulnerabilities identified",
            []
        )
        
        assert "AI Security Review" in markdown
        assert "No security vulnerabilities" in markdown


# Integration tests (require actual API key)
@pytest.mark.skipif(
    not os.getenv("LLM_API_KEY"),
    reason="Integration tests require LLM_API_KEY environment variable"
)
class TestIntegration:
    """Integration tests that call real LLM API."""
    
    @pytest.mark.asyncio
    async def test_full_review_flow(self):
        """Test the full review flow with real API."""
        from app.llm_client import analyze_diff
        
        result = await analyze_diff(
            diff_text=SAMPLE_DIFF,
            language="nodejs",
            framework="express"
        )
        
        assert result is not None
        assert result.summary is not None
        assert result.findings_markdown is not None
        # Verify we got a proper response structure
        assert "AI Security Review" in result.findings_markdown


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

