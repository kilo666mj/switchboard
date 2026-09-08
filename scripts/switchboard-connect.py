#!/usr/bin/env python3
"""Configure one Switchboard connection without copying a credential.

Requires Python 3.11+. Changes are validated as TOML and written atomically;
existing unrelated settings and approval overrides are preserved.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
from urllib.parse import urlparse


def validate_connection(url, token_env):
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        raise ValueError("Switchboard URL must be HTTPS without credentials, query, or fragment")
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", token_env):
        raise ValueError("invalid token environment variable name")


def configure(text, url, token_env):
    validate_connection(url, token_env)
    old = tomllib.loads(text)
    expected = copy.deepcopy(old)
    server = expected.setdefault("mcp_servers", {}).setdefault("switchboard", {})
    if "command" in server:
        raise ValueError("existing Switchboard entry uses stdio; migrate it explicitly first")
    server["url"] = url
    server["bearer_token_env_var"] = token_env
    server.setdefault("default_tools_approval_mode", "writes")
    lines = text.splitlines(keepends=True)
    start = end = None
    for index, line in enumerate(lines):
        if not re.match(r"^\s*\[.*\]\s*(?:#.*)?$", line):
            continue
        try:
            header = tomllib.loads(line)
        except tomllib.TOMLDecodeError:
            continue
        if start is not None:
            end = index
            break
        if header == {"mcp_servers": {"switchboard": {}}}:
            start = index
    if start is None:
        if "switchboard" in old.get("mcp_servers", {}):
            raise ValueError("use a [mcp_servers.switchboard] table before managed bootstrap")
        if text and not text.endswith("\n"):
            text += "\n"
        updated = text + "\n[mcp_servers.switchboard]\n" + "".join(f"{key} = {json.dumps(value)}\n" for key, value in server.items())
    else:
        end = len(lines) if end is None else end
        section = lines[start + 1:end]
        for key in ("url", "bearer_token_env_var", "default_tools_approval_mode"):
            matches = [i for i, line in enumerate(section) if re.match(rf"^\s*{key}\s*=", line)]
            if matches:
                if key != "default_tools_approval_mode":
                    section[matches[0]] = f"{key} = {json.dumps(server[key])}\n"
            else:
                if section and not section[-1].endswith("\n"):
                    section[-1] += "\n"
                section.append(f"{key} = {json.dumps(server[key])}\n")
        updated = "".join(lines[:start + 1] + section + lines[end:])
    if tomllib.loads(updated) != expected:
        raise ValueError("configuration layout cannot be safely edited; no changes written")
    return updated


def configure_json(text, url, token_env, client):
    validate_connection(url, token_env)
    old = json.loads(text) if text.strip() else {}
    updated = copy.deepcopy(old)
    key = "mcp" if client == "opencode" else "mcpServers"
    server = updated.setdefault(key, {}).setdefault("switchboard", {})
    if "command" in server:
        raise ValueError("existing Switchboard entry uses a local process; migrate explicitly")
    headers = server.setdefault("headers", {})
    if client == "opencode":
        server.update(type="remote", url=url, oauth=False, enabled=True)
        headers["Authorization"] = "Bearer {env:" + token_env + "}"
    elif client == "claude":
        server.update(type="http", url=url)
        headers["Authorization"] = "Bearer ${" + token_env + "}"
    elif client == "qwen":
        server.pop("url", None)
        server.update(httpUrl=url)
        server.setdefault("trust", False)
        headers["Authorization"] = "Bearer ${" + token_env + "}"
    else:
        raise ValueError("unsupported JSON client")
    return text if old == updated else json.dumps(updated, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=["codex", "claude", "opencode", "qwen"], default="codex")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-env", default="SWITCHBOARD_AUTH_TOKEN")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    defaults = {"codex": ".codex/config.toml", "claude": ".claude.json", "opencode": ".config/opencode/opencode.jsonc", "qwen": ".qwen/settings.json"}
    path = (args.config or Path.home() / defaults[args.client]).expanduser()
    if path.is_symlink():
        parser.error("config path must not be a symlink")
    original = path.read_text() if path.exists() else ""
    updated = configure(original, args.url, args.token_env) if args.client == "codex" else configure_json(original, args.url, args.token_env, args.client)
    changed = original != updated
    if changed and not args.check:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists():
            # A separate exclusive backup per change preserves rollback history.
            fd, backup = tempfile.mkstemp(prefix=path.name + ".pre-switchboard-", dir=path.parent)
            with os.fdopen(fd, "w") as stream:
                stream.write(original)
        fd, temporary = tempfile.mkstemp(prefix=".switchboard-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(updated)
                stream.flush()
                os.fsync(stream.fileno())
            if (path.read_text() if path.exists() else "") != original:
                raise ValueError("config changed during bootstrap; no changes written")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print(json.dumps({"changed": changed, "config": str(path)}))


if __name__ == "__main__":
    main()
