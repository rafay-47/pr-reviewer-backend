"""
Alert Collector & Normalizer (Stage 1).

Ingests alerts from:
1. GitHub Webhook payloads (`code_scanning_alert` events)
2. SARIF 2.1.0 JSON files / outputs (standard format from CodeQL, Semgrep, Snyk, etc.)
3. GitHub Code Scanning REST API

Normalizes all scanner outputs into standard `NormalizedAlert` objects with complete
CodeQL dataflow paths (`threadFlows` / `codeFlows`).
"""

import logging
import re
from typing import Dict, Any, List, Optional
import httpx

from .models_alert import (
    NormalizedAlert,
    CodeFlowNode,
    CodeFlowPath,
    AlertSeverity,
)

logger = logging.getLogger(__name__)


def _map_severity(severity_str: Optional[Any]) -> AlertSeverity:
    """Normalize severity string or numeric score into AlertSeverity enum."""
    if severity_str is None:
        return AlertSeverity.MEDIUM

    # Check numeric CVSS score (e.g. 8.5 or "8.5")
    try:
        val = float(severity_str)
        if val >= 9.0:
            return AlertSeverity.CRITICAL
        elif val >= 7.0:
            return AlertSeverity.HIGH
        elif val >= 4.0:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    except (ValueError, TypeError):
        pass

    s = str(severity_str).strip().upper()
    if s in ("CRITICAL", "VERY_HIGH"):
        return AlertSeverity.CRITICAL
    elif s in ("HIGH", "ERROR"):
        return AlertSeverity.HIGH
    elif s in ("MEDIUM", "MODERATE", "WARNING"):
        return AlertSeverity.MEDIUM
    elif s in ("LOW", "NOTE", "RECOMMENDATION"):
        return AlertSeverity.LOW
    return AlertSeverity.MEDIUM


def _extract_cwe_from_tags(tags: Optional[List[str]]) -> List[str]:
    """Extract normalized CWE identifiers like 'CWE-89' from CodeQL rule tags."""
    if not tags:
        return []

    cwes = []
    cwe_pattern = re.compile(r"external/cwe/cwe-(\d+)", re.IGNORECASE)
    alt_pattern = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

    for tag in tags:
        match = cwe_pattern.search(tag)
        if match:
            cwe_num = int(match.group(1))
            cwes.append(f"CWE-{cwe_num}")
            continue
        alt_match = alt_pattern.search(tag)
        if alt_match:
            cwe_num = int(alt_match.group(1))
            cwes.append(f"CWE-{cwe_num}")

    return sorted(list(set(cwes)))


def parse_github_alert_webhook(payload: Dict[str, Any]) -> Optional[NormalizedAlert]:
    """
    Parse a GitHub `code_scanning_alert` webhook payload into NormalizedAlert.
    
    Args:
        payload: Full webhook payload dictionary.
        
    Returns:
        NormalizedAlert instance, or None if payload is not an alert creation/reopen event.
    """
    action = payload.get("action")
    if action not in ("created", "reopened_by_user", "appeared_in_branch", "reopened"):
        logger.info(f"Ignoring code_scanning_alert with action: {action}")
        return None

    repo_data = payload.get("repository", {})
    repo_name = repo_data.get("full_name") or f"{repo_data.get('owner', {}).get('login', 'unknown')}/{repo_data.get('name', 'unknown')}"
    
    alert_data = payload.get("alert", {})
    alert_number = alert_data.get("number")
    alert_id = f"{repo_name}#{alert_number}"
    
    rule = alert_data.get("rule", {})
    rule_id = rule.get("id") or "unknown-rule"
    rule_name = rule.get("name") or rule_id
    rule_desc = rule.get("description") or rule.get("full_description") or rule_name
    
    # Severity
    raw_sev = rule.get("security_severity_level") or alert_data.get("severity") or rule.get("severity")
    severity = _map_severity(raw_sev)
    
    # CWEs
    cwes = _extract_cwe_from_tags(rule.get("tags", []))
    
    # Tool info
    tool = alert_data.get("tool", {})
    tool_name = tool.get("name", "CodeQL")
    tool_version = tool.get("version")
    
    # Most recent instance contains commit and location
    inst = alert_data.get("most_recent_instance", {})
    commit_sha = inst.get("commit_sha") or payload.get("commit_oid") or "HEAD"
    ref = inst.get("ref") or payload.get("ref")
    
    location_data = inst.get("location", {})
    primary_location = CodeFlowNode(
        file_path=location_data.get("path", "unknown"),
        line_number=location_data.get("start_line", 1),
        column=location_data.get("start_column"),
        end_line=location_data.get("end_line"),
        end_column=location_data.get("end_column"),
        step_type="sink",
        description=inst.get("message", {}).get("text", "Vulnerability location")
    )
    
    # If instances include path/flow data (e.g. enhanced payload or SARIF snippet)
    code_flows: List[CodeFlowPath] = []
    if "code_flows" in inst:
        for idx, flow in enumerate(inst["code_flows"]):
            nodes = []
            for n_idx, node in enumerate(flow.get("nodes", [])):
                nodes.append(CodeFlowNode(
                    file_path=node.get("path", primary_location.file_path),
                    line_number=node.get("line", 1),
                    column=node.get("column"),
                    code_snippet=node.get("snippet"),
                    function_name=node.get("function"),
                    description=node.get("message"),
                    step_type="source" if n_idx == 0 else ("sink" if n_idx == len(flow["nodes"]) - 1 else "step")
                ))
            if nodes:
                code_flows.append(CodeFlowPath(path_id=f"flow_{idx+1}", nodes=nodes))
                
    # If no explicit code_flows provided in instance, create minimal path with source and sink
    if not code_flows:
        code_flows.append(CodeFlowPath(
            path_id="flow_1",
            nodes=[
                CodeFlowNode(
                    file_path=primary_location.file_path,
                    line_number=primary_location.line_number,
                    column=primary_location.column,
                    step_type="sink",
                    description="Primary scanner finding location"
                )
            ]
        ))
        
    scanner_message = inst.get("message", {}).get("text") or alert_data.get("html_url") or "Code scanning finding"

    return NormalizedAlert(
        alert_id=alert_id,
        repo=repo_name,
        commit_sha=commit_sha,
        ref=ref,
        tool_name=tool_name,
        tool_version=tool_version,
        rule_id=rule_id,
        rule_name=rule_name,
        rule_description=rule_desc,
        severity=severity,
        cwe_ids=cwes,
        primary_location=primary_location,
        code_flows=code_flows,
        scanner_message=scanner_message,
        source_url=alert_data.get("html_url"),
        raw_scanner_output=payload
    )


def parse_sarif(sarif_data: Dict[str, Any], repo: str, commit_sha: str, ref: Optional[str] = None) -> List[NormalizedAlert]:
    """
    Parse a SARIF v2.1.0 JSON dictionary into a list of NormalizedAlert objects.
    
    Extracts full CodeQL threadFlows (source -> intermediaries -> sink).
    
    Args:
        sarif_data: Dict representing parsed SARIF JSON.
        repo: Repository slug ("owner/repo").
        commit_sha: Commit SHA analyzed.
        ref: Branch or PR reference.
        
    Returns:
        List of NormalizedAlert instances.
    """
    alerts: List[NormalizedAlert] = []
    runs = sarif_data.get("runs", [])
    
    for run_idx, run in enumerate(runs):
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "CodeQL")
        tool_version = tool.get("version")
        
        # Build rule dictionary for rapid lookup
        rule_map = {}
        for r in tool.get("rules", []):
            rule_id = r.get("id")
            if rule_id:
                rule_map[rule_id] = r
                
        results = run.get("results", [])
        for res_idx, res in enumerate(results):
            rule_id = res.get("ruleId", f"rule_{res_idx}")
            rule_info = rule_map.get(rule_id, {})
            
            rule_name = rule_info.get("name") or rule_info.get("shortDescription", {}).get("text") or rule_id
            rule_desc = rule_info.get("fullDescription", {}).get("text") or rule_info.get("help", {}).get("text") or rule_name
            
            # Severity & CWE extraction
            tags = rule_info.get("properties", {}).get("tags", [])
            cwes = _extract_cwe_from_tags(tags)
            
            raw_sev = (
                rule_info.get("properties", {}).get("security-severity")
                or res.get("level")
                or rule_info.get("defaultConfiguration", {}).get("level")
            )
            severity = _map_severity(raw_sev)
            
            # Primary location
            locations = res.get("locations", [])
            if locations:
                p_loc = locations[0].get("physicalLocation", {})
                artifact_uri = p_loc.get("artifactLocation", {}).get("uri", "unknown")
                region = p_loc.get("region", {})
                primary_location = CodeFlowNode(
                    file_path=artifact_uri,
                    line_number=region.get("startLine", 1),
                    column=region.get("startColumn"),
                    end_line=region.get("endLine"),
                    end_column=region.get("endColumn"),
                    code_snippet=region.get("snippet", {}).get("text"),
                    step_type="sink",
                    description=res.get("message", {}).get("text", "Alert finding location")
                )
            else:
                primary_location = CodeFlowNode(
                    file_path="unknown",
                    line_number=1,
                    step_type="sink",
                    description="Unknown location"
                )
                
            # Parse codeFlows & threadFlows (CodeQL taint tracks)
            code_flows: List[CodeFlowPath] = []
            sarif_code_flows = res.get("codeFlows", [])
            for cf_idx, cf in enumerate(sarif_code_flows):
                for tf_idx, tf in enumerate(cf.get("threadFlows", [])):
                    flow_nodes: List[CodeFlowNode] = []
                    tf_locations = tf.get("locations", [])
                    total_hops = len(tf_locations)
                    
                    for hop_idx, loc_item in enumerate(tf_locations):
                        loc = loc_item.get("location", {})
                        phys = loc.get("physicalLocation", {})
                        uri = phys.get("artifactLocation", {}).get("uri", primary_location.file_path)
                        reg = phys.get("region", {})
                        step_msg = loc.get("message", {}).get("text")
                        
                        # Determine step type
                        step_type = "step"
                        if hop_idx == 0:
                            step_type = "source"
                        elif hop_idx == total_hops - 1:
                            step_type = "sink"
                            
                        flow_nodes.append(CodeFlowNode(
                            file_path=uri,
                            line_number=reg.get("startLine", 1),
                            column=reg.get("startColumn"),
                            end_line=reg.get("endLine"),
                            end_column=reg.get("endColumn"),
                            code_snippet=reg.get("snippet", {}).get("text"),
                            description=step_msg,
                            step_type=step_type
                        ))
                        
                    if flow_nodes:
                        code_flows.append(CodeFlowPath(
                            path_id=f"flow_{cf_idx+1}_{tf_idx+1}",
                            nodes=flow_nodes
                        ))
                        
            # If no codeFlows exist in SARIF, create a single node flow
            if not code_flows:
                code_flows.append(CodeFlowPath(
                    path_id="flow_1",
                    nodes=[primary_location]
                ))
                
            alert_id = f"{repo}#{rule_id}_{run_idx}_{res_idx}"
            scanner_message = res.get("message", {}).get("text", "Code scanning finding")

            alerts.append(NormalizedAlert(
                alert_id=alert_id,
                repo=repo,
                commit_sha=commit_sha,
                ref=ref,
                tool_name=tool_name,
                tool_version=tool_version,
                rule_id=rule_id,
                rule_name=rule_name,
                rule_description=rule_desc,
                severity=severity,
                cwe_ids=cwes,
                primary_location=primary_location,
                code_flows=code_flows,
                scanner_message=scanner_message,
                raw_scanner_output=res
            ))
            
    return alerts


async def fetch_alert_from_github_api(
    owner: str,
    repo: str,
    alert_number: int,
    github_token: str
) -> NormalizedAlert:
    """
    Fetch code scanning alert details and instances from GitHub REST API.
    
    Args:
        owner: Repo owner/org.
        repo: Repo name.
        alert_number: Code scanning alert integer number.
        github_token: GitHub API token (Bearer / installation token).
        
    Returns:
        NormalizedAlert instance.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        alert_data = resp.json()
        
        # Also attempt to fetch instances
        instances_url = f"{url}/instances"
        inst_resp = await client.get(instances_url, headers=headers)
        instances = inst_resp.json() if inst_resp.status_code == 200 else []

    repo_full = f"{owner}/{repo}"
    payload_mock = {
        "action": "created",
        "repository": {"full_name": repo_full},
        "alert": alert_data,
        "instances": instances
    }
    
    normalized = parse_github_alert_webhook(payload_mock)
    if not normalized:
        raise ValueError(f"Could not normalize alert data for {repo_full}#{alert_number}")
        
    return normalized
