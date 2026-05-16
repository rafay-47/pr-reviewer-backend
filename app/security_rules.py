"""
Security rules and context helpers.

Provides additional context and rules for security analysis
based on language, framework, and common vulnerability patterns.
"""

from typing import Optional


# OWASP Top 10 2021 Categories
OWASP_TOP_10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# Common CWEs mapped to vulnerability types
COMMON_CWES = {
    "sql_injection": "CWE-89",
    "nosql_injection": "CWE-943",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "hardcoded_credentials": "CWE-798",
    "weak_crypto": "CWE-327",
    "weak_random": "CWE-330",
    "missing_auth": "CWE-306",
    "broken_auth": "CWE-287",
    "idor": "CWE-639",
    "open_redirect": "CWE-601",
    "sensitive_data_exposure": "CWE-200",
    "missing_encryption": "CWE-311",
    "improper_input_validation": "CWE-20",
    "prototype_pollution": "CWE-1321",
    "regex_dos": "CWE-1333",
}


def get_language_context(language: str) -> dict:
    """
    Get language-specific security context and common patterns.
    
    Args:
        language: The programming language (nodejs, python, java, etc.)
        
    Returns:
        Dictionary with language-specific security information
    """
    contexts = {
        "nodejs": {
            "name": "Node.js / JavaScript / TypeScript",
            "common_vulns": [
                "Prototype pollution",
                "Command injection via child_process",
                "NoSQL injection with MongoDB",
                "SQL injection with raw queries",
                "XSS through template engines",
                "Path traversal with fs module",
                "ReDoS with complex regex",
                "Insecure deserialization",
                "JWT misconfigurations",
            ],
            "dangerous_functions": [
                "eval()",
                "Function()",
                "child_process.exec()",
                "child_process.spawn() with shell:true",
                "vm.runInContext()",
                "new Function()",
                "setTimeout/setInterval with strings",
                "innerHTML/outerHTML",
                "document.write()",
            ],
            "secure_patterns": [
                "Use parameterized queries (prepared statements)",
                "Use child_process.spawn() without shell option",
                "Validate and sanitize all user input",
                "Use helmet.js for HTTP headers",
                "Use bcrypt for password hashing",
                "Use crypto.randomBytes() for secure random values",
                "Use DOMPurify for HTML sanitization",
            ],
        },
        "python": {
            "name": "Python",
            "common_vulns": [
                "SQL injection with string formatting",
                "Command injection via subprocess shell=True",
                "SSTI (Server-Side Template Injection)",
                "Pickle deserialization attacks",
                "Path traversal",
                "SSRF through requests library",
                "Weak cryptography",
            ],
            "dangerous_functions": [
                "eval()",
                "exec()",
                "pickle.loads()",
                "yaml.load() without SafeLoader",
                "subprocess.call() with shell=True",
                "os.system()",
                "__import__()",
                "compile()",
            ],
            "secure_patterns": [
                "Use SQLAlchemy ORM or parameterized queries",
                "Use subprocess with shell=False",
                "Use yaml.safe_load()",
                "Use secrets module for random values",
                "Use pathlib for safe path handling",
            ],
        },
        "java": {
            "name": "Java",
            "common_vulns": [
                "SQL injection",
                "XXE in XML parsers",
                "Deserialization vulnerabilities",
                "Path traversal",
                "LDAP injection",
                "Expression Language injection",
                "Log injection (Log4j style)",
            ],
            "dangerous_functions": [
                "Runtime.exec()",
                "ProcessBuilder with untrusted input",
                "ObjectInputStream.readObject()",
                "XMLInputFactory (without XXE protection)",
                "Statement.execute() with concatenation",
                "String.format() in SQL queries",
            ],
            "secure_patterns": [
                "Use PreparedStatement for SQL",
                "Disable external entities in XML parsers",
                "Use ObjectInputFilter for deserialization",
                "Validate file paths with canonical path check",
            ],
        },
    }
    
    return contexts.get(language.lower(), {
        "name": language,
        "common_vulns": [],
        "dangerous_functions": [],
        "secure_patterns": [],
    })


def get_framework_context(framework: str) -> dict:
    """
    Get framework-specific security context.
    
    Args:
        framework: The web framework (express, fastapi, spring, etc.)
        
    Returns:
        Dictionary with framework-specific security information
    """
    contexts = {
        "express": {
            "name": "Express.js",
            "security_features": [
                "helmet middleware for HTTP headers",
                "express-rate-limit for rate limiting",
                "express-validator for input validation",
                "csurf for CSRF protection",
                "express-session for session management",
            ],
            "common_misconfigs": [
                "Missing helmet() middleware",
                "Disabled CORS without proper origin checks",
                "Trust proxy misconfiguration",
                "Session cookies without secure flags",
                "Missing rate limiting on auth endpoints",
            ],
            "auth_patterns": [
                "passport.js integration",
                "JWT with express-jwt",
                "Session-based auth with express-session",
            ],
        },
        "fastapi": {
            "name": "FastAPI",
            "security_features": [
                "Built-in OAuth2 support",
                "Pydantic validation",
                "Dependency injection for auth",
                "CORS middleware",
            ],
            "common_misconfigs": [
                "Overly permissive CORS",
                "Missing authentication dependencies",
                "Exposed debug endpoints",
                "SQL injection in raw queries",
            ],
            "auth_patterns": [
                "OAuth2PasswordBearer",
                "API key authentication",
                "JWT token validation",
            ],
        },
        "spring": {
            "name": "Spring Boot / Spring Security",
            "security_features": [
                "Spring Security for authentication/authorization",
                "Built-in CSRF protection",
                "Method-level security annotations",
                "OAuth2 resource server",
            ],
            "common_misconfigs": [
                "Disabled CSRF protection",
                "Overly permissive security configurations",
                "Missing @PreAuthorize annotations",
                "Exposed actuator endpoints",
            ],
            "auth_patterns": [
                "@PreAuthorize / @Secured annotations",
                "WebSecurityConfigurerAdapter",
                "JWT with Spring Security",
            ],
        },
    }
    
    return contexts.get(framework.lower(), {
        "name": framework,
        "security_features": [],
        "common_misconfigs": [],
        "auth_patterns": [],
    })


def build_security_hints(language: str, framework: str) -> str:
    """
    Build security hints text to augment the LLM prompt.
    
    Args:
        language: Programming language
        framework: Web framework
        
    Returns:
        Formatted string with relevant security hints
    """
    lang_ctx = get_language_context(language)
    fw_ctx = get_framework_context(framework)
    
    hints = []
    
    if lang_ctx.get("dangerous_functions"):
        funcs = ", ".join(lang_ctx["dangerous_functions"][:5])
        hints.append(f"Watch for dangerous functions in {lang_ctx['name']}: {funcs}")
    
    if fw_ctx.get("common_misconfigs"):
        configs = "; ".join(fw_ctx["common_misconfigs"][:3])
        hints.append(f"Common {fw_ctx['name']} misconfigurations: {configs}")
    
    return "\n".join(hints) if hints else ""


def get_vulnerability_metadata(vuln_type: str) -> dict:
    """
    Get OWASP and CWE metadata for a vulnerability type.
    
    Args:
        vuln_type: Type of vulnerability (e.g., "sql_injection", "xss")
        
    Returns:
        Dictionary with owasp and cwe fields
    """
    vuln_mapping = {
        "sql_injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-89"},
        "nosql_injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-943"},
        "command_injection": {"owasp": "A03:2021 Injection", "cwe": "CWE-78"},
        "xss": {"owasp": "A03:2021 Injection", "cwe": "CWE-79"},
        "path_traversal": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-22"},
        "ssrf": {"owasp": "A10:2021 Server-Side Request Forgery", "cwe": "CWE-918"},
        "idor": {"owasp": "A01:2021 Broken Access Control", "cwe": "CWE-639"},
        "broken_auth": {"owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-287"},
        "hardcoded_secret": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-798"},
        "weak_crypto": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-327"},
        "deserialization": {"owasp": "A08:2021 Software and Data Integrity Failures", "cwe": "CWE-502"},
        "sensitive_exposure": {"owasp": "A02:2021 Cryptographic Failures", "cwe": "CWE-200"},
    }
    
    return vuln_mapping.get(vuln_type.lower(), {"owasp": "", "cwe": ""})
