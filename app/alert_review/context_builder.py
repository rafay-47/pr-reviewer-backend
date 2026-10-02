"""
Code Context Builder (Stage 2).

Reconstructs the execution and dataflow environment around CodeQL alerts
at the analyzed commit SHA:
- Fetches source files at commit SHA (local checkout or GitHub API)
- Extracts scoped code slices around source, intermediary steps, and sink
- Identifies enclosing function/method boundaries
- Extracts imported dependencies, ORMs, and security middlewares
"""

import logging
import re
import os
from typing import Dict, Any, List, Optional, Callable, Awaitable
import httpx

from .models_alert import (
    NormalizedAlert,
    AlertCodeContext,
    CodeContextSnippet,
    CodeFlowNode,
)

logger = logging.getLogger(__name__)

FRAMEWORK_SIGNATURES = {
    "express": [r"require\(['\"]express['\"]\)", r"from ['\"]express['\"]", r"express\(\)"],
    "fastapi": [r"from fastapi import", r"import fastapi", r"FastAPI\("],
    "flask": [r"from flask import", r"import flask", r"Flask\(__name__\)"],
    "django": [r"from django", r"django\."],
    "spring": [r"@SpringBootApplication", r"@RestController", r"@RequestMapping"],
    "nextjs": [r"from ['\"]next/", r"next/server"],
}

DATABASE_SIGNATURES = {
    "prisma": [r"@prisma/client", r"prisma\."],
    "typeorm": [r"typeorm", r"@Entity", r"getRepository"],
    "sqlalchemy": [r"from sqlalchemy", r"import sqlalchemy", r"session\.query", r"select\("],
    "mongoose": [r"mongoose", r"new Schema"],
    "knex": [r"knex\(", r"require\(['\"]knex['\"]\)", r"from ['\"]knex['\"]"],
    "raw_sql": [r"\.query\(", r"\.execute\(", r"cursor\.execute"],
}

SECURITY_MIDDLEWARE_SIGNATURES = {
    "helmet": [r"helmet\(\)", r"require\(['\"]helmet['\"]\)", r"from ['\"]helmet['\"]"],
    "cors": [r"cors\(\)", r"CORSMiddleware"],
    "csurf": [r"csurf\(\)", r"csrf"],
    "zod_validator": [r"z\.object", r"from ['\"]zod['\"]"],
    "joi_validator": [r"Joi\.", r"from ['\"]joi['\"]"],
    "pydantic_validator": [r"BaseModel", r"from pydantic"],
}


def _extract_enclosing_block(lines: List[str], target_line_idx: int) -> tuple[int, int, Optional[str]]:
    """
    Heuristically determine enclosing function/block boundaries around target line.
    
    Args:
        lines: 0-indexed list of file lines.
        target_line_idx: 0-indexed line index of target code.
        
    Returns:
        (start_line_1_based, end_line_1_based, enclosing_symbol_name)
    """
    total_lines = len(lines)
    if total_lines == 0 or target_line_idx < 0 or target_line_idx >= total_lines:
        return 1, min(20, total_lines), None

    # Search backwards for function/class def
    func_pattern = re.compile(
        r"^\s*(async\s+)?(def|function|class)\s+([a-zA-Z0-9_$]+)"
        r"|^\s*(const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(async\s*)?\("
        r"|^\s*([a-zA-Z0-9_$]+)\s*\(.*\)\s*\{"
    )

    start_idx = max(0, target_line_idx - 10)
    symbol_name = None

    for idx in range(target_line_idx, -1, -1):
        line = lines[idx]
        m = func_pattern.search(line)
        if m:
            start_idx = idx
            # Extract first non-empty group
            groups = [g for g in m.groups() if g and g not in ("async", "def", "function", "class", "const", "let", "var")]
            if groups:
                symbol_name = groups[0]
            break

    # Look ahead 15 lines past target or to next closing brace / def
    end_idx = min(total_lines - 1, target_line_idx + 12)
    return start_idx + 1, end_idx + 1, symbol_name


def _analyze_imports_and_env(full_text: str) -> tuple[List[str], List[str], List[str], List[str]]:
    """Extract imported modules, frameworks, and security layers from file text."""
    if not isinstance(full_text, str):
        full_text = str(full_text) if full_text is not None else ""
    imports = []
    frameworks = []
    db_layers = []
    middlewares = []

    # Import statement matching
    import_regex = re.compile(r"^\s*(?:import\s+(?:.*?\s+from\s+)?['\"]([^'\"]+)['\"]|const\s+.*?=\s*require\(['\"]([^'\"]+)['\"]\))", re.MULTILINE)
    for match in import_regex.finditer(full_text):
        mod = match.group(1) or match.group(2)
        if mod:
            imports.append(mod)

    # Framework detection
    for fw_name, patterns in FRAMEWORK_SIGNATURES.items():
        if any(re.search(p, full_text, re.IGNORECASE) for p in patterns):
            frameworks.append(fw_name)

    # Database / ORM detection
    for db_name, patterns in DATABASE_SIGNATURES.items():
        if any(re.search(p, full_text, re.IGNORECASE) for p in patterns):
            db_layers.append(db_name)

    # Security middleware detection
    for sec_name, patterns in SECURITY_MIDDLEWARE_SIGNATURES.items():
        if any(re.search(p, full_text, re.IGNORECASE) for p in patterns):
            middlewares.append(sec_name)

    return sorted(list(set(imports))), sorted(list(set(frameworks))), sorted(list(set(db_layers))), sorted(list(set(middlewares)))


class CodeContextBuilder:
    """Builder for assembling complete code context bundles for static alerts."""

    def __init__(
        self,
        local_repo_path: Optional[str] = None,
        github_token: Optional[str] = None,
        file_reader_override: Optional[Callable[[str, str], Awaitable[Optional[str]]]] = None
    ):
        """
        Args:
            local_repo_path: Path to root of cloned repo if available.
            github_token: Token for querying GitHub Contents/Blobs API.
            file_reader_override: Custom async hook (path, commit_sha) -> content string.
        """
        self.local_repo_path = local_repo_path
        self.github_token = github_token
        self.file_reader_override = file_reader_override
        self._file_cache: Dict[str, str] = {}

    async def get_file_content(self, repo: str, file_path: str, commit_sha: str) -> Optional[str]:
        """Fetch content of a file at specific commit SHA with caching."""
        cache_key = f"{repo}:{commit_sha}:{file_path}"
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]

        # 1. Custom override hook
        if self.file_reader_override:
            try:
                content = await self.file_reader_override(file_path, commit_sha)
                if content is not None:
                    self._file_cache[cache_key] = content
                    return content
            except Exception as e:
                logger.warning(f"file_reader_override failed for {file_path}: {e}")

        # 2. Local checkout
        if self.local_repo_path:
            full_path = os.path.join(self.local_repo_path, file_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        self._file_cache[cache_key] = content
                        return content
                except Exception as e:
                    logger.warning(f"Error reading local file {full_path}: {e}")

        # 3. GitHub API
        if self.github_token and repo:
            try:
                owner, repo_name = repo.split("/", 1)
                headers = {
                    "Accept": "application/vnd.github.raw+json",
                    "Authorization": f"Bearer {self.github_token}",
                    "X-GitHub-Api-Version": "2022-11-28"
                }
                url = f"https://api.github.com/repos/{owner}/{repo_name}/contents/{file_path}?ref={commit_sha}"
                async with httpx.AsyncClient(timeout=20.0) as client:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        content = resp.text
                        self._file_cache[cache_key] = content
                        return content
            except Exception as e:
                logger.warning(f"GitHub API fetch failed for {file_path}: {e}")

        return None

    async def build_context(self, alert: NormalizedAlert) -> AlertCodeContext:
        """
        Build an enriched code context bundle for a NormalizedAlert.
        
        Args:
            alert: NormalizedAlert instance.
            
        Returns:
            AlertCodeContext instance.
        """
        source_slices: List[CodeContextSnippet] = []
        path_slices: List[CodeContextSnippet] = []
        sink_slices: List[CodeContextSnippet] = []

        all_imports: List[str] = []
        all_frameworks: List[str] = []
        all_middlewares: List[str] = []
        related_files: List[str] = []

        # Collect unique nodes to slice
        nodes_to_process: List[CodeFlowNode] = [alert.primary_location]
        for flow in alert.code_flows:
            nodes_to_process.extend(flow.nodes)

        # De-duplicate nodes by file and line
        seen_nodes = set()
        unique_nodes = []
        for n in nodes_to_process:
            key = (n.file_path, n.line_number)
            if key not in seen_nodes:
                seen_nodes.add(key)
                unique_nodes.append(n)

        for node in unique_nodes:
            if not node.file_path or node.file_path == "unknown":
                continue

            if node.file_path not in related_files:
                related_files.append(node.file_path)

            content = await self.get_file_content(alert.repo, node.file_path, alert.commit_sha)
            if not content:
                # If file content could not be read, use snippet if available
                snippet_text = node.code_snippet or f"// [Code unavailable for {node.file_path}:{node.line_number}]"
                snippet = CodeContextSnippet(
                    file_path=node.file_path,
                    start_line=node.line_number,
                    end_line=node.line_number,
                    content=snippet_text,
                    role=node.step_type
                )
            else:
                lines = content.splitlines()
                target_idx = max(0, node.line_number - 1)
                start_l, end_l, sym_name = _extract_enclosing_block(lines, target_idx)
                
                slice_content = "\n".join(lines[start_l - 1: end_l])
                snippet = CodeContextSnippet(
                    file_path=node.file_path,
                    start_line=start_l,
                    end_line=end_l,
                    content=slice_content,
                    enclosing_symbol=sym_name or node.function_name,
                    role=node.step_type
                )

                # Extract imports and framework signals from file
                imports, frameworks, dbs, middlewares = _analyze_imports_and_env(content)
                all_imports.extend(imports)
                all_frameworks.extend(frameworks)
                all_frameworks.extend(dbs)
                all_middlewares.extend(middlewares)

            if node.step_type == "source":
                source_slices.append(snippet)
            elif node.step_type == "sink":
                sink_slices.append(snippet)
            else:
                path_slices.append(snippet)

        # If primary location wasn't explicitly classified as sink, ensure sink_slices has it
        if not sink_slices and source_slices:
            sink_slices.append(source_slices[-1])

        # Estimate tokens (~4 characters per token)
        total_chars = sum(len(s.content) for s in (source_slices + path_slices + sink_slices))
        token_estimate = max(100, total_chars // 4)

        return AlertCodeContext(
            alert_id=alert.alert_id,
            commit_sha=alert.commit_sha,
            source_slices=source_slices,
            path_slices=path_slices,
            sink_slices=sink_slices,
            related_files=related_files,
            imported_modules=sorted(list(set(all_imports))),
            detected_frameworks=sorted(list(set(all_frameworks))),
            detected_middleware=sorted(list(set(all_middlewares))),
            context_token_estimate=token_estimate
        )
