"""
GitHub API client for repository management and workflow installation.

Provides async functions for:
- Listing user repositories
- Creating/updating files (for workflow installation)
- Checking file existence
- Managing repository secrets
"""

import base64
import logging
from urllib.parse import quote
from typing import Optional
from dataclasses import dataclass

import httpx
from nacl import encoding, public

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

# The security review workflow template
SECURITY_REVIEW_WORKFLOW = '''name: AI AppSec PR Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

# Prevent concurrent runs for the same PR
concurrency:
  group: ai-security-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    name: Security Review
    
    # Don't run on draft PRs (they're not ready for review)
    if: github.event.pull_request.draft == false
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history needed for diff
      
      - name: Get PR Diff
        id: diff
        run: |
          # Get the diff between base and head
          DIFF=$(git diff origin/${{ github.base_ref }}...HEAD)
          
          # Save to file to handle multiline content
          echo "$DIFF" > /tmp/pr_diff.txt
          
          # Get diff size for logging
          DIFF_SIZE=$(wc -c < /tmp/pr_diff.txt)
          echo "diff_size=$DIFF_SIZE" >> $GITHUB_OUTPUT
          
          # Get changed file names for logging (safe to log)
          CHANGED_FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | head -20)
          echo "Changed files:"
          echo "$CHANGED_FILES"
      
      - name: Load Repository Policy
        id: policy
        run: |
          # Check if .aiappsec.yml exists in the repo
          if [ -f ".aiappsec.yml" ]; then
            echo "Found .aiappsec.yml policy file"
            POLICY=$(cat .aiappsec.yml)
            echo "policy_found=true" >> $GITHUB_OUTPUT
            # Convert YAML to JSON for the API
            echo "$POLICY" > /tmp/policy.yml
          elif [ -f ".aiappsec.yaml" ]; then
            echo "Found .aiappsec.yaml policy file"
            POLICY=$(cat .aiappsec.yaml)
            echo "policy_found=true" >> $GITHUB_OUTPUT
            echo "$POLICY" > /tmp/policy.yml
          else
            echo "No policy file found, using defaults"
            echo "policy_found=false" >> $GITHUB_OUTPUT
          fi
      
      # Extract fingerprints from existing comment BEFORE running review
      - name: Find Existing Comment and Extract Fingerprints
        id: find_comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });
            
            // Find comment with our hidden marker
            const marker = '<!-- AI_APPSEC_REVIEW -->';
            const existingComment = comments.find(comment => 
              comment.body && comment.body.includes(marker)
            );
            
            let fingerprints = [];
            
            if (existingComment) {
              console.log(`Found existing comment: ${existingComment.id}`);
              
              // Try to extract fingerprints from comment
              const fpMatch = existingComment.body.match(/<!-- FINGERPRINTS:(.*?)-->/);
              if (fpMatch) {
                try {
                  fingerprints = JSON.parse(fpMatch[1]);
                  console.log(`Extracted ${fingerprints.length} fingerprints for dedup`);
                } catch (e) {
                  console.log('Failed to parse fingerprints from comment');
                }
              }
              
              // Save fingerprints for the review step
              fs.writeFileSync('/tmp/previous_fingerprints.json', JSON.stringify(fingerprints));
              
              return existingComment.id;
            }
            
            console.log('No existing comment found');
            fs.writeFileSync('/tmp/previous_fingerprints.json', '[]');
            return '';
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install pyyaml httpx
      
      - name: Run Security Review
        id: review
        env:
          AIAPPSEC_API_URL: ${{ secrets.AI_REVIEW_URL }}
          AIAPPSEC_API_TOKEN: ${{ secrets.AI_REVIEW_TOKEN }}
          AIAPPSEC_HMAC_SECRET: ${{ secrets.AIAPPSEC_HMAC_SECRET }}
          AIAPPSEC_TENANT_ID: ${{ secrets.AI_REVIEW_TENANT_ID }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python << 'EOF'
          import os
          import sys
          import json
          import time
          import hmac
          import hashlib
          import textwrap
          import yaml
          import httpx
          
          # Configuration
          api_url = os.environ.get('AIAPPSEC_API_URL', 'http://localhost:8000')
          api_token = os.environ.get('AIAPPSEC_API_TOKEN', '')
          hmac_secret = os.environ.get('AIAPPSEC_HMAC_SECRET', '')
          tenant_id = os.environ.get('AIAPPSEC_TENANT_ID', '')
          
          # Read the diff
          with open('/tmp/pr_diff.txt', 'r') as f:
              diff = f.read()
          
          if not diff.strip():
              print("No changes detected in PR")
              with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                  f.write("findings_count=0\\n")
                  f.write("needs_comment=false\\n")
                  f.write("should_block=false\\n")
                  f.write("policy_mode=advisory\\n")
              sys.exit(0)
          
          # Load policy if exists
          policy = None
          policy_mode = "advisory"  # Default mode
          fail_on = "HIGH"  # Default fail_on
          if os.path.exists('/tmp/policy.yml'):
              with open('/tmp/policy.yml', 'r') as f:
                  try:
                      yaml_policy = yaml.safe_load(f)
                      if yaml_policy:
                          policy_mode = yaml_policy.get('mode', 'advisory')
                          fail_on = yaml_policy.get('fail_on', 'HIGH')
                          policy = {
                              "mode": policy_mode,
                              "fail_on": fail_on,
                              "max_findings": yaml_policy.get('max_findings', 10),
                              "min_risk": yaml_policy.get('min_risk', 'LOW'),
                              "min_confidence": yaml_policy.get('min_confidence', 'LOW'),
                              "blocklist": yaml_policy.get('blocklist', yaml_policy.get('block_paths', [])),
                              "rules": yaml_policy.get('rules', {}),
                          }
                          print(f"Policy loaded: mode={policy_mode}, fail_on={fail_on}")
                  except yaml.YAMLError as e:
                      print(f"Warning: Failed to parse policy file: {e}")
          
          # Load previous fingerprints from existing comment (for deduplication)
          previous_fingerprints = []
          fingerprints_file = '/tmp/previous_fingerprints.json'
          if os.path.exists(fingerprints_file):
              try:
                  with open(fingerprints_file, 'r') as f:
                      previous_fingerprints = json.load(f)
                  print(f"Loaded {len(previous_fingerprints)} previous fingerprints for dedup")
              except:
                  pass
          
          # Build request payload
          payload = {
              "repo": "${{ github.repository }}",
              "pr_number": ${{ github.event.pull_request.number }},
              "language": "nodejs",  # Could be detected from repo
              "framework": "express",  # Could be detected from package.json
              "diff": diff,
              "previous_fingerprints": previous_fingerprints,
          }
          
          if policy:
              payload["policy"] = policy
          
          # Add HMAC signature if secret is configured
          headers = {"Content-Type": "application/json"}
          
          if api_token:
              headers["Authorization"] = f"Bearer {api_token}"
          
          if tenant_id:
              headers["X-Tenant-ID"] = tenant_id
          
          if hmac_secret:
              timestamp = int(time.time())
              # Create payload for signing (without signature fields)
              sign_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))
              message = f"{timestamp}.{sign_payload}".encode('utf-8')
              signature = hmac.new(
                  hmac_secret.encode('utf-8'),
                  message,
                  hashlib.sha256
              ).hexdigest()
              payload["signature"] = signature
              payload["timestamp"] = timestamp
          
          # Make the API request
          print(f"Sending review request to {api_url}/review-pr")
          print(f"Diff size: {len(diff)} characters")
          
          review_failed = False
          error_message = ""
          
          try:
              response = httpx.post(
                  f"{api_url}/review-pr",
                  json=payload,
                  headers=headers,
                  timeout=180.0  # 3 minute timeout for large diffs
              )
              response.raise_for_status()
              result = response.json()
              
              findings_count = len(result.get('findings', []))
              needs_review_count = len(result.get('needs_manual_review', []))
              findings_hash = result.get('findings_hash', '')
              markdown = result.get('findings_markdown', '')
              should_block = result.get('should_block', False)
              fingerprints = result.get('fingerprints', [])
              new_count = result.get('new_findings_count', findings_count)
              still_present = result.get('still_present_count', 0)
              resolved_count = result.get('resolved_findings_count', 0)
              
              print(f"Review completed: {findings_count} findings ({new_count} new, {still_present} still present, {resolved_count} resolved)")
              print(f"Needs review: {needs_review_count}")
              print(f"Should block: {should_block}")
              
              # Save results
              with open('/tmp/review_result.json', 'w') as f:
                  json.dump(result, f)
              
              with open('/tmp/comment_body.md', 'w') as f:
                  f.write(markdown)
              
              # Save fingerprints for deduplication in next run
              with open('/tmp/fingerprints.json', 'w') as f:
                  json.dump(fingerprints, f)
              
              with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                  f.write(f"findings_count={findings_count}\\n")
                  f.write(f"new_findings_count={new_count}\\n")
                  f.write(f"still_present_count={still_present}\\n")
                  f.write(f"resolved_count={resolved_count}\\n")
                  f.write(f"needs_review_count={needs_review_count}\\n")
                  f.write(f"findings_hash={findings_hash}\\n")
                  f.write(f"needs_comment=true\\n")  # Always post a comment now
                  f.write(f"should_block={'true' if should_block else 'false'}\\n")
                  f.write(f"policy_mode={policy_mode}\\n")
                  f.write(f"fail_on={fail_on}\\n")
                  f.write(f"review_failed=false\\n")
                  
          except httpx.HTTPStatusError as e:
              print(f"API error: {e.response.status_code}")
              review_failed = True
              error_message = f"HTTP {e.response.status_code}"
              
              # Create error comment
              error_markdown = textwrap.dedent(f"""\\
                  ## 🔒 AI Security Review
                  
                  <!-- AI_APPSEC_REVIEW -->
                  <!-- FINGERPRINTS:[]-->
                  
                  **⚠️ AI review failed: API error**
                  
                  **Error:** `{error_message}`
                  
                  ---
                  
                  💡 Please retry by pushing a new commit or re-running the workflow.
                  
                  ---
                  *AI AppSec PR Reviewer*""")
              
              with open('/tmp/comment_body.md', 'w') as f:
                  f.write(error_markdown)
              
              with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                  f.write(f"findings_count=0\\n")
                  f.write(f"needs_comment=true\\n")
                  f.write(f"should_block=false\\n")
                  f.write(f"policy_mode={policy_mode}\\n")
                  f.write(f"review_failed=true\\n")
                  
          except httpx.TimeoutException:
              print("API request timed out")
              review_failed = True
              error_message = "timeout"
              
              error_markdown = textwrap.dedent(f"""\\
                  ## 🔒 AI Security Review
                  
                  <!-- AI_APPSEC_REVIEW -->
                  <!-- FINGERPRINTS:[]-->
                  
                  **⏱️ AI review timed out**
                  
                  The security review request timed out. This may be due to a large diff or service issues.
                  
                  ---
                  
                  💡 Please retry by pushing a new commit or re-running the workflow.
                  
                  ---
                  *AI AppSec PR Reviewer*""")
              
              with open('/tmp/comment_body.md', 'w') as f:
                  f.write(error_markdown)
              
              with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                  f.write(f"findings_count=0\\n")
                  f.write(f"needs_comment=true\\n")
                  f.write(f"should_block=false\\n")
                  f.write(f"policy_mode={policy_mode}\\n")
                  f.write(f"review_failed=true\\n")
                  
          except Exception as e:
              print(f"Error: {type(e).__name__}")
              review_failed = True
              error_message = type(e).__name__
              
              error_markdown = textwrap.dedent(f"""\\
                  ## 🔒 AI Security Review
                  
                  <!-- AI_APPSEC_REVIEW -->
                  <!-- FINGERPRINTS:[]-->
                  
                  **⚠️ AI review failed**
                  
                  An unexpected error occurred during the security review.
                  
                  **Error Type:** `{error_message}`
                  
                  ---
                  
                  💡 Please retry by pushing a new commit or re-running the workflow.
                  
                  ---
                  *AI AppSec PR Reviewer*""")
              
              with open('/tmp/comment_body.md', 'w') as f:
                  f.write(error_markdown)
              
              with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                  f.write(f"findings_count=0\\n")
                  f.write(f"needs_comment=true\\n")
                  f.write(f"should_block=false\\n")
                  f.write(f"policy_mode={policy_mode}\\n")
                  f.write(f"review_failed=true\\n")
          EOF
      
      - name: Create or Update PR Comment
        if: steps.review.outputs.needs_comment == 'true'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const commentBody = fs.readFileSync('/tmp/comment_body.md', 'utf8');
            const existingCommentId = '${{ steps.find_comment.outputs.result }}';
            
            if (existingCommentId && existingCommentId !== '""' && existingCommentId !== '') {
              // Update existing comment
              const commentIdNum = parseInt(existingCommentId.replace(/"/g, ''));
              console.log(`Updating comment ${commentIdNum}`);
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: commentIdNum,
                body: commentBody
              });
            } else {
              // Create new comment
              console.log('Creating new comment');
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: commentBody
              });
            }
      
      - name: Report Status
        if: always()
        run: |
          echo "## Security Review Summary" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          
          if [ "${{ steps.review.outputs.findings_count }}" != "" ]; then
            echo "- **Findings:** ${{ steps.review.outputs.findings_count }} (${{ steps.review.outputs.new_findings_count }} new, ${{ steps.review.outputs.still_present_count }} still present)" >> $GITHUB_STEP_SUMMARY
            if [ "${{ steps.review.outputs.resolved_count }}" != "0" ]; then
              echo "- **✅ Resolved:** ${{ steps.review.outputs.resolved_count }} issues fixed since last review" >> $GITHUB_STEP_SUMMARY
            fi
            echo "- **Needs Manual Review:** ${{ steps.review.outputs.needs_review_count }}" >> $GITHUB_STEP_SUMMARY
            echo "- **Findings Hash:** \\`${{ steps.review.outputs.findings_hash }}\\`" >> $GITHUB_STEP_SUMMARY
            echo "- **Policy Mode:** ${{ steps.review.outputs.policy_mode }}" >> $GITHUB_STEP_SUMMARY
            echo "- **Fail On:** ${{ steps.review.outputs.fail_on }}" >> $GITHUB_STEP_SUMMARY
            echo "- **Should Block:** ${{ steps.review.outputs.should_block }}" >> $GITHUB_STEP_SUMMARY
          else
            echo "- Review did not complete successfully" >> $GITHUB_STEP_SUMMARY
          fi
      
      - name: Enforce Gate (Block PR)
        if: steps.review.outputs.should_block == 'true' && steps.review.outputs.policy_mode == 'enforce'
        run: |
          echo "::error::Security review found vulnerabilities exceeding the fail_on threshold (${{ steps.review.outputs.fail_on }}). PR blocked by enforce mode policy."
          echo "## ❌ PR Blocked" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "This PR has been blocked due to security findings that meet or exceed the **${{ steps.review.outputs.fail_on }}** risk threshold." >> $GITHUB_STEP_SUMMARY
          echo "Please address the security issues and push a new commit." >> $GITHUB_STEP_SUMMARY
          exit 1
'''

WORKFLOW_VERSION = "1.0.0"
WORKFLOW_PATH = ".github/workflows/security-review.yml"


@dataclass
class GitHubRepo:
    """GitHub repository information."""
    id: int
    name: str
    full_name: str
    owner: str
    private: bool
    description: Optional[str]
    default_branch: str
    html_url: str
    permissions: dict


@dataclass
class WorkflowStatus:
    """Workflow installation status."""
    installed: bool
    path: str
    sha: Optional[str] = None
    version: Optional[str] = None


class GitHubClient:
    """Async GitHub API client."""
    
    def __init__(self, access_token: str):
        self.access_token = access_token
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        
    def _get_headers(self) -> dict:
        """Get headers with conditional preview for private repos."""
        headers = self.headers.copy()
        # Enable preview for private repository access
        headers["Accept"] = "application/vnd.github+json, application/vnd.github.v3+json"
        return headers
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make an authenticated request to GitHub API."""
        async with httpx.AsyncClient() as client:
            url = f"{GITHUB_API_BASE}{endpoint}"
            response = await client.request(
                method,
                url,
                headers=self._get_headers(),
                json=json,
                params=params,
                timeout=30.0,
            )
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            
            if response.status_code == 204:
                return {}
            
            return response.json()
    
    async def get_user(self) -> dict:
        """Get the authenticated user."""
        return await self._request("GET", "/user")
    
    async def list_repos(
        self,
        per_page: int = 100,
        page: int = 1,
        sort: str = "updated",
        affiliation: str = "owner,collaborator,organization_member",
    ) -> list[GitHubRepo]:
        """
        List repositories for the authenticated user.
        
        Args:
            per_page: Number of repos per page (max 100)
            page: Page number
            sort: Sort by (created, updated, pushed, full_name)
            affiliation: Filter by affiliation (owner, collaborator, organization_member)
        
        Returns:
            List of GitHubRepo objects
        """
        params = {
            "per_page": per_page,
            "page": page,
            "sort": sort,
            "affiliation": affiliation,
        }
        
        data = await self._request("GET", "/user/repos", params=params)
        
        if not data:
            return []
        
        repos = []
        for repo in data:
            repos.append(GitHubRepo(
                id=repo["id"],
                name=repo["name"],
                full_name=repo["full_name"],
                owner=repo["owner"]["login"],
                private=repo["private"],
                description=repo.get("description"),
                default_branch=repo.get("default_branch", "main"),
                html_url=repo["html_url"],
                permissions=repo.get("permissions", {}),
            ))
        
        return repos
    
    async def list_all_repos(self, max_repos: int = 500) -> list[GitHubRepo]:
        """
        List all repositories for the authenticated user (paginated).
        
        Args:
            max_repos: Maximum number of repos to fetch
        
        Returns:
            List of all GitHubRepo objects
        """
        all_repos = []
        page = 1
        per_page = 100
        
        while len(all_repos) < max_repos:
            repos = await self.list_repos(per_page=per_page, page=page)
            if not repos:
                break
            
            all_repos.extend(repos)
            
            if len(repos) < per_page:
                break
            
            page += 1
        
        return all_repos[:max_repos]
    
    async def list_installation_repos(self, max_repos: int = 500) -> list[GitHubRepo]:
        """
        List repositories accessible to a GitHub App installation.
        
        Uses the /installation/repositories endpoint which is only available
        to GitHub App installation tokens.
        
        Args:
            max_repos: Maximum number of repos to fetch
            
        Returns:
            List of GitHubRepo objects accessible to the installation
        """
        all_repos = []
        page = 1
        per_page = 100
        
        while len(all_repos) < max_repos:
            params = {"per_page": per_page, "page": page}
            data = await self._request("GET", "/installation/repositories", params=params)
            
            if not data or "repositories" not in data:
                break
            
            repos_data = data["repositories"]
            if not repos_data:
                break
            
            for repo in repos_data:
                permissions = repo.get("permissions", {})
                all_repos.append(GitHubRepo(
                    id=repo["id"],
                    name=repo["name"],
                    full_name=repo["full_name"],
                    owner=repo["owner"]["login"],
                    private=repo["private"],
                    description=repo.get("description"),
                    default_branch=repo.get("default_branch", "main"),
                    html_url=repo["html_url"],
                    permissions=permissions,
                ))
            
            if len(repos_data) < per_page:
                break
            
            page += 1
        
        return all_repos[:max_repos]
    
    async def get_repo(self, owner: str, repo: str) -> Optional[GitHubRepo]:
        """Get a specific repository."""
        data = await self._request("GET", f"/repos/{owner}/{repo}")
        
        if not data:
            return None
        
        return GitHubRepo(
            id=data["id"],
            name=data["name"],
            full_name=data["full_name"],
            owner=data["owner"]["login"],
            private=data["private"],
            description=data.get("description"),
            default_branch=data.get("default_branch", "main"),
            html_url=data["html_url"],
            permissions=data.get("permissions", {}),
        )
    
    async def get_file(self, owner: str, repo: str, path: str) -> Optional[dict]:
        """
        Get a file from a repository.
        
        Returns:
            File content dict with 'sha', 'content', etc. or None if not found
        """
        return await self._request("GET", f"/repos/{owner}/{repo}/contents/{path}")
    
    async def check_workflow_status(self, owner: str, repo: str) -> WorkflowStatus:
        """
        Check if the security review workflow is installed.
        
        Returns:
            WorkflowStatus with installation details
        """
        file_data = await self.get_file(owner, repo, WORKFLOW_PATH)
        
        if not file_data:
            return WorkflowStatus(installed=False, path=WORKFLOW_PATH)
        
        return WorkflowStatus(
            installed=True,
            path=WORKFLOW_PATH,
            sha=file_data.get("sha"),
            version=WORKFLOW_VERSION,  # We assume current version if file exists
        )
    
    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: Optional[str] = None,
        sha: Optional[str] = None,
    ) -> dict:
        """
        Create or update a file in a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            content: File content (will be base64 encoded)
            message: Commit message
            branch: Branch name (defaults to default branch)
            sha: Current file SHA (required for updates)
        
        Returns:
            Response with commit info
        """
        # Base64 encode the content
        content_encoded = base64.b64encode(content.encode()).decode()
        
        payload = {
            "message": message,
            "content": content_encoded,
        }
        
        if branch:
            payload["branch"] = branch
        
        if sha:
            payload["sha"] = sha
        
        return await self._request(
            "PUT",
            f"/repos/{owner}/{repo}/contents/{path}",
            json=payload,
        )
    
    async def install_workflow(self, owner: str, repo: str) -> dict:
        """
        Install or update the security review workflow in a repository.
        
        Returns:
            Dict with 'success', 'action' (created/updated), 'sha'
        """
        # First check if user has write access
        repo_data = await self.get_repo(owner, repo)
        if not repo_data:
            return {
                "success": False,
                "action": "failed",
                "error": "Repository not found or access denied",
            }
        
        permissions = repo_data.permissions
        if not (permissions.get("push", False) or permissions.get("admin", False)):
            return {
                "success": False,
                "action": "failed",
                "error": "Insufficient permissions. You need push or admin access to install workflows.",
            }
        
        # Check if workflow already exists
        status = await self.check_workflow_status(owner, repo)
        
        message = (
            "Update AI AppSec security review workflow"
            if status.installed
            else "Add AI AppSec security review workflow"
        )
        
        try:
            result = await self.create_or_update_file(
                owner=owner,
                repo=repo,
                path=WORKFLOW_PATH,
                content=SECURITY_REVIEW_WORKFLOW,
                message=message,
                sha=status.sha if status.installed else None,
            )
            
            return {
                "success": True,
                "action": "updated" if status.installed else "created",
                "sha": result.get("content", {}).get("sha"),
                "commit_sha": result.get("commit", {}).get("sha"),
            }
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to install workflow in {owner}/{repo}: {e}")
            error_msg = str(e)
            
            # Provide more helpful error messages
            if e.response.status_code == 403:
                error_msg = "Permission denied. The repository may have branch protection rules or you may need the 'workflow' OAuth scope."
            elif e.response.status_code == 404:
                error_msg = "Repository not found or access denied."
            elif e.response.status_code == 422:
                error_msg = "Invalid request. The repository may not accept workflow files."
            
            return {
                "success": False,
                "action": "failed",
                "error": error_msg,
            }
        except Exception as e:
            logger.error(f"Unexpected error installing workflow in {owner}/{repo}: {e}")
            return {
                "success": False,
                "action": "failed",
                "error": f"Unexpected error: {str(e)}",
            }
    
    async def has_write_access(self, owner: str, repo: str) -> bool:
        """Check if the user has write access to a repository."""
        repo_data = await self.get_repo(owner, repo)
        if not repo_data:
            return False
        
        permissions = repo_data.permissions
        return permissions.get("push", False) or permissions.get("admin", False)

    async def get_branch_protection(self, owner: str, repo: str, branch: str) -> Optional[dict]:
        """Get branch protection configuration for a branch."""
        branch_ref = quote(branch, safe="")
        return await self._request("GET", f"/repos/{owner}/{repo}/branches/{branch_ref}/protection")

    async def ensure_required_status_check(
        self,
        owner: str,
        repo: str,
        branch: str,
        context_name: str,
    ) -> dict:
        """
        Ensure branch protection requires a given status-check context.
        """
        existing = await self.get_branch_protection(owner, repo, branch)
        current_contexts = []
        if existing:
            current_contexts = (existing.get("required_status_checks") or {}).get("contexts") or []

        merged_contexts = sorted(set(current_contexts + [context_name]))
        branch_ref = quote(branch, safe="")
        payload = {
            "required_status_checks": {"strict": True, "contexts": merged_contexts},
            "enforce_admins": False,
            "required_pull_request_reviews": None,
            "restrictions": None,
        }

        result = await self._request(
            "PUT",
            f"/repos/{owner}/{repo}/branches/{branch_ref}/protection",
            json=payload,
        )
        return {
            "success": True,
            "branch": branch,
            "required_context": context_name,
            "contexts": merged_contexts,
            "protection": result or {},
        }
    
    async def get_repo_public_key(self, owner: str, repo: str) -> dict:
        """
        Get the public key for encrypting secrets in a repository.
        
        Returns:
            Dict with 'key_id' and 'key' (base64 encoded public key)
        """
        return await self._request("GET", f"/repos/{owner}/{repo}/actions/secrets/public-key")
    
    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        """
        Encrypt a secret using the repository's public key.
        
        Args:
            public_key: Base64 encoded public key from GitHub
            secret_value: Plain text secret value
        
        Returns:
            Base64 encoded encrypted secret
        """
        # Decode the public key
        public_key_bytes = base64.b64decode(public_key)
        
        # Create a sealed box with the public key
        sealed_box = public.SealedBox(public.PublicKey(public_key_bytes))
        
        # Encrypt the secret
        encrypted = sealed_box.encrypt(secret_value.encode())
        
        # Return base64 encoded encrypted value
        return base64.b64encode(encrypted).decode()
    
    async def set_repository_secret(
        self,
        owner: str,
        repo: str,
        secret_name: str,
        secret_value: str
    ) -> dict:
        """
        Create or update a repository secret.
        
        Args:
            owner: Repository owner
            repo: Repository name
            secret_name: Name of the secret (e.g., 'AI_REVIEW_TOKEN')
            secret_value: Plain text value of the secret
        
        Returns:
            Dict with success status
        """
        # Get the repository's public key
        key_data = await self.get_repo_public_key(owner, repo)
        
        # Encrypt the secret value
        encrypted_value = self.encrypt_secret(key_data["key"], secret_value)
        
        # Set the secret
        payload = {
            "encrypted_value": encrypted_value,
            "key_id": key_data["key_id"]
        }
        
        try:
            await self._request(
                "PUT",
                f"/repos/{owner}/{repo}/actions/secrets/{secret_name}",
                json=payload
            )
            return {"success": True, "secret_name": secret_name}
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to set secret {secret_name}: {e}")
            return {"success": False, "secret_name": secret_name, "error": str(e)}
    
    async def list_repository_secrets(self, owner: str, repo: str) -> list[str]:
        """
        List all secret names in a repository (values are not returned by GitHub).
        
        Returns:
            List of secret names
        """
        try:
            response = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/actions/secrets"
            )
            return [secret["name"] for secret in response.get("secrets", [])]
        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to list secrets: {e}")
            return []


async def list_github_repos(access_token: str) -> list[dict]:
    """
    List GitHub repos for the given access token.
    
    Returns list of repo dicts with standard fields.
    """
    client = GitHubClient(access_token)
    repos = await client.list_all_repos()
    
    return [
        {
            "id": repo.id,
            "name": repo.name,
            "full_name": repo.full_name,
            "owner": repo.owner,
            "private": repo.private,
            "description": repo.description,
            "default_branch": repo.default_branch,
            "html_url": repo.html_url,
            "can_push": repo.permissions.get("push", False),
            "can_admin": repo.permissions.get("admin", False),
        }
        for repo in repos
    ]


async def check_workflow_installed(access_token: str, owner: str, repo: str) -> dict:
    """Check if workflow is installed in a repo."""
    client = GitHubClient(access_token)
    status = await client.check_workflow_status(owner, repo)
    
    return {
        "installed": status.installed,
        "path": status.path,
        "sha": status.sha,
        "version": status.version,
    }


async def install_workflow_to_repo(access_token: str, owner: str, repo: str) -> dict:
    """Install the security review workflow to a repo."""
    client = GitHubClient(access_token)
    return await client.install_workflow(owner, repo)
