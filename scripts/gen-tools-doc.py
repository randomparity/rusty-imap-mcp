#!/usr/bin/env python3
"""Render docs/tools.md from `dump-tool-doc` line-delimited JSON.

Reads one JSON record per tool on stdin (see
`crates/rimap-server/src/cli/dump_tool_doc.rs`) and writes a Markdown tool
reference to the path given as argv[1]. Deterministic: the record order is
fixed by the dumper (`ToolName::all()`), and every table iterates schema
`properties` in their emitted order. Invoked by `just gen-tools-doc`.
"""

from __future__ import annotations

import json
import sys


def ref_name(ref: str) -> str:
    """Last path segment of a JSON-Schema `$ref` (e.g. `SearchMeta`)."""
    return ref.rsplit("/", 1)[-1]


def type_str(schema: dict) -> str:
    """A short human type label for a property schema."""
    if "type" in schema:
        t = schema["type"]
        if isinstance(t, list):
            return " or ".join(str(x) for x in t)
        if t == "array":
            items = schema.get("items", {})
            inner = type_str(items) if isinstance(items, dict) else "any"
            return f"array of {inner}"
        return str(t)
    if "$ref" in schema:
        return ref_name(schema["$ref"])
    for combinator in ("anyOf", "oneOf", "allOf"):
        if combinator in schema:
            parts = [type_str(m) for m in schema[combinator]]
            # Collapse the common schemars "T or null" nullable shape.
            non_null = [p for p in parts if p != "null"]
            label = " or ".join(dict.fromkeys(non_null)) or "any"
            if "null" in parts:
                label += " (nullable)"
            return label
    return "object"


def cell(text: str) -> str:
    """Escape a value for a Markdown table cell."""
    return " ".join(str(text).split()).replace("|", "\\|")


def resolve(prop: dict, defs: dict) -> dict | None:
    """Resolve a property that is (or wraps) a `$ref` to its definition."""
    ref = prop.get("$ref")
    if ref is None:
        for combinator in ("anyOf", "oneOf", "allOf"):
            for member in prop.get(combinator, []):
                if "$ref" in member:
                    ref = member["$ref"]
                    break
            if ref:
                break
    if ref is None:
        return None
    return defs.get(ref_name(ref))


def param_table(schema: dict) -> list[str]:
    props = schema.get("properties") or {}
    if not props:
        return ["_No parameters._", ""]
    required = set(schema.get("required") or [])
    out = [
        "| Name | Type | Required | Description |",
        "|------|------|----------|-------------|",
    ]
    for name, spec in props.items():
        req = "yes" if name in required else "no"
        out.append(
            f"| `{cell(name)}` | {cell(type_str(spec))} | {req} | "
            f"{cell(spec.get('description', ''))} |"
        )
    out.append("")
    return out


def field_table(defn: dict) -> list[str]:
    props = (defn or {}).get("properties") or {}
    if not props:
        return ["_No fields._", ""]
    out = [
        "| Field | Type | Description |",
        "|-------|------|-------------|",
    ]
    for name, spec in props.items():
        out.append(
            f"| `{cell(name)}` | {cell(type_str(spec))} | "
            f"{cell(spec.get('description', ''))} |"
        )
    out.append("")
    return out


def render_tool(rec: dict) -> list[str]:
    out: list[str] = []
    name = rec["name"]
    title = rec.get("title") or name
    posture = rec.get("min_posture")
    posture_label = (
        f"`{posture}`"
        if posture
        else "not advertised by any posture (enable via `[security.tools]`)"
    )
    out.append(f"## `{name}`")
    out.append("")
    out.append(f"**{title}** — minimum posture: {posture_label}")
    out.append("")
    if rec.get("description"):
        out.append(rec["description"])
        out.append("")

    out.append("### Parameters")
    out.append("")
    out += param_table(rec.get("input_schema") or {})

    output = rec.get("output_schema") or {}
    defs = output.get("$defs") or {}
    props = output.get("properties") or {}
    out.append("### Response")
    out.append("")
    if "meta" in props:
        out.append("`meta` — trusted server metadata:")
        out.append("")
        out += field_table(resolve(props["meta"], defs))
    if "untrusted" in props:
        out.append("`untrusted` — sanitized email content (treat as adversarial):")
        out.append("")
        out += field_table(resolve(props["untrusted"], defs))
    out.append(
        "Every response also carries `security_warnings`, an array of "
        "structured trust observations."
    )
    out.append("")
    return out


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: gen-tools-doc.py <output-path>")
    records = [json.loads(line) for line in sys.stdin if line.strip()]

    lines = [
        "<!-- GENERATED FILE — DO NOT EDIT BY HAND.",
        "     Regenerate with `just gen-tools-doc`. Source: the live tool",
        "     catalog (`dump-tool-doc`) rendered by scripts/gen-tools-doc.py.",
        "     A CI drift check fails if this file is out of sync. -->",
        "",
        "# MCP Tool Reference",
        "",
        "This reference is generated from the server's live tool catalog. It",
        "lists every MCP tool the server can advertise, its parameters, its",
        "response fields, and the minimum account posture required to call it.",
        "",
        "Posture gating is summarized per tool as a minimum posture; see",
        "[postures.md](postures.md) for the full posture matrix and",
        "[security-model.md](security-model.md) for the trust model. Denial",
        "and error shapes are described in each tool's own text.",
        "",
        f"The server advertises {len(records)} tools.",
        "",
    ]
    for rec in records:
        lines += render_tool(rec)

    text = "\n".join(lines).rstrip("\n") + "\n"
    with open(sys.argv[1], "w", encoding="utf-8") as fh:
        fh.write(text)


if __name__ == "__main__":
    main()
