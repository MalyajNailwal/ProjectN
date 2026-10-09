"""Inventory a supplied OpenAPI file without executing its requests or resolving remote references."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import yaml

from app.core import gap, public_url

METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
MAX_BYTES = 5 * 1024 * 1024
MAX_ROUTES = 20000


def route_pattern(path: str) -> re.Pattern[str]:
    fragments = [re.escape(item) for item in re.split(r"(\{[^{}]+\})", path) if item]
    fragments = [r"[^/]+" if item.startswith(r"\{") and item.endswith(r"\}") else item for item in fragments]
    return re.compile("^" + "".join(fragments).rstrip("/") + "/?$")


def inspect_api_spec(path: Path, target_url: str, observed: list[dict]) -> tuple[list[dict], dict, list[dict]]:
    label = "OpenAPI contract inventory"
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("OpenAPI file exceeds the 5 MiB limit")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not (isinstance(data.get("openapi"), str) or data.get("swagger") == "2.0"):
            raise ValueError("File is not an OpenAPI 3 or Swagger 2 document")
        paths = data.get("paths")
        if not isinstance(paths, dict):
            raise ValueError("OpenAPI paths must be an object")
        target = urlparse(target_url)
        servers = data.get("servers") if isinstance(data.get("servers"), list) else []
        bases = []
        unresolved_servers = 0
        if data.get("swagger") == "2.0":
            bases = [str(data.get("basePath", "/"))]
        elif servers:
            for server in servers:
                raw = server.get("url") if isinstance(server, dict) else None
                if not isinstance(raw, str) or "{" in raw or "}" in raw:
                    unresolved_servers += 1
                    continue
                parsed_server = urlparse(urljoin(target_url, raw))
                if parsed_server.scheme == target.scheme and parsed_server.netloc == target.netloc:
                    bases.append(parsed_server.path or "/")
        else:
            bases = ["/"]
        bases = list(dict.fromkeys(bases))
        declared = []
        for route, operations in paths.items():
            if not isinstance(route, str) or not route.startswith("/") or not isinstance(operations, dict):
                continue
            for base in bases:
                effective_path = "/" + "/".join(part for part in (base.strip("/"), route.strip("/")) if part)
                for method in operations:
                    if method.lower() in METHODS:
                        declared.append({"method": method.upper(), "path": effective_path})
                        if len(declared) > MAX_ROUTES:
                            raise ValueError("OpenAPI document exceeds the route limit")
        seen = []
        for item in observed:
            address = urlparse(item.get("url", ""))
            if address.scheme != target.scheme or address.netloc != target.netloc:
                continue
            seen.append({"method": str(item.get("method", "GET")).upper(), "url": public_url(item["url"]), "path": address.path or "/", "status": item.get("status")})
        seen = list({(item["method"], item["url"]): item for item in seen}.values())
        patterns = [(item, route_pattern(item["path"])) for item in declared]
        for item, pattern in patterns:
            item["observed"] = any(seen_item["method"] == item["method"] and pattern.fullmatch(seen_item["path"]) for seen_item in seen)
        undocumented = [item for item in seen if not any(spec_item["method"] == item["method"] and pattern.fullmatch(item["path"]) for spec_item, pattern in patterns)]
        details = {"declared": declared, "declared_count": len(declared), "observed_count": len(seen), "declared_observed_count": sum(item["observed"] for item in declared), "undocumented_observed": undocumented, "unresolved_servers": unresolved_servers, "matching_server_paths": bases, "spec_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        gaps = []
        if unresolved_servers or not bases:
            gaps.append(gap("api_server_unresolved", "Some API server URLs could not be matched to the selected website origin.", "Use concrete in-scope server URLs or provide a specification with resolved server variables.", "api_spec"))
        if any(not item["observed"] for item in declared):
            gaps.append(gap("api_routes_not_observed", f"{sum(not item['observed'] for item in declared)} documented API operation(s) were not observed in this scan.", "Provide scoped authenticated traffic or journeys for those routes, then reassess; a missing observation does not prove an endpoint is unavailable.", "api_spec"))
        if undocumented:
            gaps.append(gap("api_routes_undocumented", f"{len(undocumented)} observed endpoint(s) are absent from the supplied API specification.", "Review whether the specification is current and whether these endpoints should be documented.", "api_spec"))
        return [], {"id": "api_spec", "label": label, "state": "partial" if unresolved_servers or not bases else "completed", "summary": f"{len(declared)} declared; {len(seen)} observed; {len(undocumented)} undocumented observed", "details": details}, gaps
    except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError) as exc:
        return [], {"id": "api_spec", "label": label, "state": "failed", "summary": type(exc).__name__}, [gap("api_spec_invalid", str(exc)[:200], "Provide a valid local OpenAPI JSON or YAML file within the size and route limits.", "api_spec")]
