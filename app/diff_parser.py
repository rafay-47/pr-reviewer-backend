"""
Git diff parsing and chunking utilities.

Provides functions to parse git diffs into reviewable chunks
with file and line context for security analysis.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class DiffHunk:
    """Represents a single hunk (change block) within a file."""
    header: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    content: str
    
    @property
    def line_range(self) -> str:
        """Get the line range string for this hunk."""
        if self.new_count == 1:
            return str(self.new_start)
        return f"{self.new_start}-{self.new_start + self.new_count - 1}"


@dataclass
class FileDiff:
    """Represents all changes to a single file."""
    old_path: Optional[str]
    new_path: str
    is_new_file: bool
    is_deleted: bool
    is_renamed: bool
    hunks: list[DiffHunk]
    
    @property
    def path(self) -> str:
        """Get the current file path."""
        return self.new_path if self.new_path else self.old_path
    
    @property
    def added_lines(self) -> list[tuple[int, str]]:
        """Get all added lines with their line numbers."""
        lines = []
        for hunk in self.hunks:
            current_line = hunk.new_start
            for line in hunk.content.split('\n'):
                if line.startswith('+') and not line.startswith('+++'):
                    lines.append((current_line, line[1:]))
                if not line.startswith('-') or line.startswith('---'):
                    current_line += 1
        return lines
    
    @property
    def full_content(self) -> str:
        """Get the full diff content for this file."""
        parts = []
        if self.is_new_file:
            parts.append(f"new file: {self.new_path}")
        elif self.is_deleted:
            parts.append(f"deleted file: {self.old_path}")
        elif self.is_renamed:
            parts.append(f"renamed: {self.old_path} -> {self.new_path}")
        else:
            parts.append(f"modified: {self.new_path}")
        
        for hunk in self.hunks:
            parts.append(hunk.header)
            parts.append(hunk.content)
        
        return '\n'.join(parts)


@dataclass
class ParsedDiff:
    """Complete parsed git diff containing all file changes."""
    files: list[FileDiff]
    raw_diff: str
    
    @property
    def file_count(self) -> int:
        """Number of files changed."""
        return len(self.files)
    
    @property
    def total_additions(self) -> int:
        """Total number of lines added."""
        return sum(
            len([l for l in h.content.split('\n') if l.startswith('+') and not l.startswith('+++')])
            for f in self.files for h in f.hunks
        )
    
    @property
    def total_deletions(self) -> int:
        """Total number of lines deleted."""
        return sum(
            len([l for l in h.content.split('\n') if l.startswith('-') and not l.startswith('---')])
            for f in self.files for h in f.hunks
        )
    
    def get_security_relevant_files(self) -> list[FileDiff]:
        """
        Filter to files that are more likely to contain security issues.
        
        Prioritizes:
        - Controllers, routes, handlers
        - Authentication/authorization code
        - Database queries
        - API endpoints
        - Configuration files
        """
        security_patterns = [
            r'controller',
            r'route',
            r'handler',
            r'auth',
            r'login',
            r'password',
            r'session',
            r'token',
            r'api',
            r'database',
            r'db',
            r'query',
            r'sql',
            r'config',
            r'secret',
            r'middleware',
            r'security',
            r'crypto',
            r'encrypt',
            r'upload',
            r'file',
        ]
        pattern = '|'.join(security_patterns)
        
        relevant = []
        for file_diff in self.files:
            path_lower = file_diff.path.lower()
            # Check if filename matches security patterns
            if re.search(pattern, path_lower, re.IGNORECASE):
                relevant.append(file_diff)
            # Also include if content has security-sensitive changes
            elif self._has_security_sensitive_content(file_diff):
                relevant.append(file_diff)
        
        return relevant if relevant else self.files
    
    def _has_security_sensitive_content(self, file_diff: FileDiff) -> bool:
        """Check if the diff content contains security-sensitive patterns."""
        sensitive_patterns = [
            r'password',
            r'secret',
            r'api[_-]?key',
            r'token',
            r'auth',
            r'session',
            r'cookie',
            r'sql',
            r'query',
            r'exec\(',
            r'eval\(',
            r'innerHTML',
            r'dangerouslySetInnerHTML',
            r'\.query\(',
            r'\.execute\(',
            r'child_process',
            r'spawn\(',
            r'exec\(',
            r'readFile',
            r'writeFile',
            r'crypto',
            r'bcrypt',
            r'jwt',
            r'Bearer',
            r'Authorization',
        ]
        pattern = '|'.join(sensitive_patterns)
        
        for hunk in file_diff.hunks:
            if re.search(pattern, hunk.content, re.IGNORECASE):
                return True
        return False


def parse_diff(diff_text: str) -> ParsedDiff:
    """
    Parse a git diff into structured components.
    
    Args:
        diff_text: Raw git diff output
        
    Returns:
        ParsedDiff object containing all file changes
    """
    if not diff_text or not diff_text.strip():
        return ParsedDiff(files=[], raw_diff=diff_text)
    
    files = []
    
    # Split diff by file
    file_pattern = r'^diff --git a/(.+?) b/(.+?)$'
    file_splits = re.split(file_pattern, diff_text, flags=re.MULTILINE)
    
    # First element is empty or content before first diff
    i = 1
    while i < len(file_splits) - 1:
        old_path = file_splits[i]
        new_path = file_splits[i + 1]
        
        # Get the content up to the next file diff
        if i + 3 < len(file_splits):
            next_diff_match = re.search(r'^diff --git', file_splits[i + 2], re.MULTILINE)
            if next_diff_match:
                content = file_splits[i + 2][:next_diff_match.start()]
            else:
                content = file_splits[i + 2]
        else:
            content = file_splits[i + 2] if i + 2 < len(file_splits) else ""
        
        # Parse file metadata
        is_new_file = 'new file mode' in content
        is_deleted = 'deleted file mode' in content
        is_renamed = old_path != new_path
        
        # Parse hunks
        hunks = _parse_hunks(content)
        
        files.append(FileDiff(
            old_path=old_path if not is_new_file else None,
            new_path=new_path if not is_deleted else old_path,
            is_new_file=is_new_file,
            is_deleted=is_deleted,
            is_renamed=is_renamed,
            hunks=hunks
        ))
        
        i += 3
    
    return ParsedDiff(files=files, raw_diff=diff_text)


def _parse_hunks(content: str) -> list[DiffHunk]:
    """Parse individual hunks from file diff content."""
    hunks = []
    
    # Match hunk headers: @@ -old_start,old_count +new_start,new_count @@
    hunk_pattern = r'^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$'
    
    lines = content.split('\n')
    current_hunk = None
    hunk_lines = []
    
    for line in lines:
        match = re.match(hunk_pattern, line)
        if match:
            # Save previous hunk if exists
            if current_hunk:
                current_hunk.content = '\n'.join(hunk_lines)
                hunks.append(current_hunk)
            
            # Start new hunk
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1
            context = match.group(5).strip()
            
            current_hunk = DiffHunk(
                header=line,
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                content=""
            )
            hunk_lines = []
        elif current_hunk is not None:
            # Filter out Git's "No newline at end of file" marker
            if line == "\ No newline at end of file" or line == "\\ No newline at end of file":
                continue
            hunk_lines.append(line)
    
    # Save last hunk
    if current_hunk:
        current_hunk.content = '\n'.join(hunk_lines)
        hunks.append(current_hunk)
    
    return hunks


def chunk_diff_for_review(parsed_diff: ParsedDiff, max_chunk_size: int = 8000) -> list[str]:
    """
    Split a parsed diff into chunks suitable for LLM review.
    
    Tries to keep files together, but will split large files
    across multiple chunks if necessary.
    
    Args:
        parsed_diff: The parsed diff to chunk
        max_chunk_size: Maximum characters per chunk
        
    Returns:
        List of diff text chunks
    """
    if not parsed_diff.files:
        return []
    
    chunks = []
    current_chunk = []
    current_size = 0
    
    for file_diff in parsed_diff.files:
        file_content = file_diff.full_content
        file_size = len(file_content)
        
        # If single file is larger than max, split by hunks
        if file_size > max_chunk_size:
            # Flush current chunk first
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = []
                current_size = 0
            
            # Split file by hunks
            for hunk in file_diff.hunks:
                hunk_content = f"File: {file_diff.path}\n{hunk.header}\n{hunk.content}"
                if len(hunk_content) > max_chunk_size:
                    # Extremely large hunk - just truncate with note
                    chunks.append(hunk_content[:max_chunk_size] + "\n... (truncated)")
                else:
                    chunks.append(hunk_content)
        
        # Check if adding this file would exceed limit
        elif current_size + file_size > max_chunk_size:
            # Save current chunk and start new one
            if current_chunk:
                chunks.append('\n\n'.join(current_chunk))
            current_chunk = [file_content]
            current_size = file_size
        else:
            # Add to current chunk
            current_chunk.append(file_content)
            current_size += file_size
    
    # Don't forget the last chunk
    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))
    
    return chunks


def build_review_context(
    parsed_diff: ParsedDiff,
    language: str,
    framework: str
) -> dict:
    """
    Build context information for the security review.
    
    Args:
        parsed_diff: The parsed diff
        language: Programming language
        framework: Web framework
        
    Returns:
        Dictionary with context information
    """
    return {
        "language": language,
        "framework": framework,
        "file_count": parsed_diff.file_count,
        "total_additions": parsed_diff.total_additions,
        "total_deletions": parsed_diff.total_deletions,
        "files_changed": [f.path for f in parsed_diff.files],
        "security_relevant_files": [f.path for f in parsed_diff.get_security_relevant_files()],
    }
