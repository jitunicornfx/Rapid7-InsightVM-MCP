#!/usr/bin/env python3
"""Generate the MCP tool catalog from the bundled Rapid7 InsightVM OpenAPI specifications.

Reads  specs/insightvm-console-v3.json  (Security Console API v3)
       specs/insightvm-cloud-v4.json    (Insight Platform Cloud Integrations API v4)
Writes src/main/resources/catalog/v3.json and v4.json.

The catalog is a compact, pre-dereferenced description of every operation: the runtime
(`catalog/CatalogTools.kt`) registers one MCP tool per entry and never parses the raw
specs. Output is deterministic so `--check` can detect drift between specs and catalog.

Standard library only. Run:   python tools/gen_catalog.py          (regenerate)
                              python tools/gen_catalog.py --check  (verify, exit 1 on drift)
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT / "specs"
OUT_DIR = ROOT / "src" / "main" / "resources" / "catalog"

GENERATOR_VERSION = "gen_catalog.py@1"
MAX_DESCRIPTION = 600
MAX_DEPTH = 8
HTTP_METHODS = ("get", "post", "put", "delete", "patch")
DESTRUCTIVE_OPID = re.compile(r"^(delete|remove|stop)", re.IGNORECASE)
ADMIN_OPS = {("POST", "/api/3/administration/commands")}
STRIP_KEYS = {"example", "examples", "xml", "title", "deprecated", "discriminator", "externalDocs"}

FAMILIES = [
    # (family id, spec file, output file, tool-name prefix)
    ("console", "insightvm-console-v3.json", "v3.json", ""),
    ("cloud", "insightvm-cloud-v4.json", "v4.json", "cloud_"),
]


class CatalogError(Exception):
    pass


# --------------------------------------------------------------------------- text helpers
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(text: str | None, limit: int | None = MAX_DESCRIPTION) -> str:
    """Strip HTML, unescape entities, collapse whitespace, drop control chars, cap length."""
    if not text:
        return ""
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    text = _CTRL_RE.sub("", text)
    text = _WS_RE.sub(" ", text).strip()
    # Re-neutralise anything that could be read as markup after unescaping.
    text = text.replace("<", "‹").replace(">", "›")
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def snake_case(op_id: str) -> str:
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", op_id)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"[^a-zA-Z0-9]+", "_", s).lower().strip("_")
    return re.sub(r"_+", "_", s)


# --------------------------------------------------------------------------- schema inlining
class Inliner:
    def __init__(self, components: dict):
        self.schemas = components.get("schemas", {})

    def resolve_ref(self, ref: str) -> tuple[str, dict]:
        prefix = "#/components/schemas/"
        if not ref.startswith(prefix):
            raise CatalogError(f"unsupported $ref: {ref}")
        name = ref[len(prefix):]
        if name not in self.schemas:
            raise CatalogError(f"unknown schema: {name}")
        return name, self.schemas[name]

    def inline(self, schema, depth: int = 0, stack: tuple[str, ...] = ()):
        if not isinstance(schema, dict):
            return schema
        if "$ref" in schema:
            name, target = self.resolve_ref(schema["$ref"])
            if name in stack or depth > MAX_DEPTH:
                return {"type": "object", "description": f"{name} (nested object; see the Rapid7 API documentation)"}
            merged = self.inline(target, depth + 1, stack + (name,))
            extra = {k: v for k, v in schema.items() if k != "$ref" and k == "description"}
            if isinstance(merged, dict):
                merged = {**merged, **extra}
            return merged

        out: dict = {}
        for key, value in schema.items():
            if key in STRIP_KEYS:
                continue
            if key == "properties" and isinstance(value, dict):
                props = {}
                for pname, pschema in value.items():
                    if isinstance(pschema, dict) and pschema.get("readOnly") is True:
                        continue  # server-assigned; never meaningful in a request body
                    props[pname] = self.inline(pschema, depth + 1, stack)
                out["properties"] = props
            elif key == "items":
                out["items"] = self.inline(value, depth + 1, stack)
            elif key == "additionalProperties":
                out["additionalProperties"] = self.inline(value, depth + 1, stack) if isinstance(value, dict) else value
            elif key in ("allOf", "oneOf", "anyOf") and isinstance(value, list):
                out[key] = [self.inline(v, depth + 1, stack) for v in value]
            elif key == "description":
                out["description"] = clean_text(value, 400)
            elif key == "readOnly":
                continue
            else:
                out[key] = value
        if "properties" in out and isinstance(out.get("required"), list):
            out["required"] = [r for r in out["required"] if r in out["properties"]]
            if not out["required"]:
                del out["required"]
        return out


# --------------------------------------------------------------------------- parameters
def normalize_param_schema(schema: dict | None, inliner: Inliner) -> tuple[dict, bool]:
    schema = inliner.inline(schema or {})
    if not isinstance(schema, dict):
        schema = {}
    if "type" not in schema:
        if "enum" in schema:
            schema["type"] = "string"
        elif "items" in schema:
            schema["type"] = "array"
        elif "format" in schema and schema["format"] in ("int32", "int64"):
            schema["type"] = "integer"
        elif "default" in schema and isinstance(schema["default"], bool):
            schema["type"] = "boolean"
        elif "default" in schema and isinstance(schema["default"], int):
            schema["type"] = "integer"
        else:
            schema["type"] = "string"
    is_array = schema.get("type") == "array"
    if is_array:
        items = schema.get("items")
        if not isinstance(items, dict) or not items:
            items = {"type": "string"}
        if "enum" in schema and "enum" not in items:
            items = {**items, "enum": schema.pop("enum")}
        if "type" not in items:
            items["type"] = "string"
        schema["items"] = items
    return schema, is_array


def build_params(op: dict, inliner: Inliner, family: str) -> list[dict]:
    params = []
    seen = set()
    for p in op.get("parameters", []):
        if "$ref" in p:
            raise CatalogError("parameter $ref not supported")
        where = p.get("in")
        name = p.get("name")
        if where not in ("path", "query"):
            continue  # header/cookie params are never model-controlled
        if family == "cloud" and where == "path" and name == "region":
            continue  # supplied by configuration, not by the caller
        if name == "body":
            raise CatalogError(f"parameter named 'body' collides with the request body property ({op.get('operationId')})")
        if name in seen:
            raise CatalogError(f"duplicate parameter {name} in {op.get('operationId')}")
        seen.add(name)
        schema, is_array = normalize_param_schema(p.get("schema"), inliner)
        desc = clean_text(p.get("description"), 400)
        if desc:
            schema["description"] = desc
        params.append({
            "name": name,
            "in": where,
            "required": bool(p.get("required", False)) or where == "path",
            "array": is_array,
            "schema": schema,
        })
    return params


def build_body(op: dict, inliner: Inliner) -> dict | None:
    rb = op.get("requestBody")
    if not rb:
        return None
    content = rb.get("content", {})
    if "application/json" in content:
        schema = inliner.inline(content["application/json"].get("schema", {}))
        if not isinstance(schema, dict) or not schema:
            schema = {"type": "object"}
        if "type" not in schema:
            schema["type"] = "object"
        return {"contentType": "application/json", "required": bool(rb.get("required", False)), "schema": schema}
    if "text/plain" in content:
        schema = {"type": "string"}
        desc = clean_text(rb.get("description"), 400)
        if desc:
            schema["description"] = desc
        return {"contentType": "text/plain", "required": bool(rb.get("required", False)), "schema": schema}
    raise CatalogError(f"unsupported request body content types {list(content)} in {op.get('operationId')}")


def success_content_type(op: dict) -> tuple[str, bool]:
    for code in sorted(op.get("responses", {})):
        if not code.startswith("2"):
            continue
        content = op["responses"][code].get("content") or {}
        if not content:
            return "none", False
        ct = next(iter(content))
        if "json" in ct:
            return "application/json", False
        if ct.startswith("text/html"):
            return "text/html", False
        if ct.startswith("text/plain"):
            return "text/plain", False
        if ct in ("application/zip", "application/octet-stream") or "zip" in ct:
            return ct, True
        return ct, True
    return "none", False


# --------------------------------------------------------------------------- generation
def build_catalog(family: str, spec: dict, prefix: str, spec_sha: str, source: str) -> dict:
    inliner = Inliner(spec.get("components", {}))
    ops = []
    for path, item in spec["paths"].items():
        if "parameters" in item:
            raise CatalogError(f"path-level parameters not supported ({path})")
        for method in HTTP_METHODS:
            op = item.get(method)
            if not op:
                continue
            op_id = op.get("operationId")
            if not op_id:
                raise CatalogError(f"missing operationId for {method.upper()} {path}")
            upper = method.upper()
            name = prefix + snake_case(op_id)
            read_only = upper == "GET"
            destructive = upper == "DELETE" or bool(DESTRUCTIVE_OPID.match(op_id))
            admin = (upper, path) in ADMIN_OPS
            summary = clean_text(op.get("summary"), 120)
            description = clean_text(op.get("description"))
            tag = (op.get("tags") or ["Untagged"])[0]
            success, binary = success_content_type(op)
            body = build_body(op, inliner)
            entry = {
                "name": name,
                "opId": op_id,
                "method": upper,
                "path": path,
                "tag": tag,
                "summary": summary,
                "description": description,
                "readOnly": read_only,
                "destructive": destructive,
                "admin": admin,
                "params": build_params(op, inliner, family),
                "body": body,
                "responses": {"success": success, "binary": binary},
            }
            ops.append(entry)
    ops.sort(key=lambda o: (o["path"], o["method"]))
    meta = {
        "family": family,
        "title": spec.get("info", {}).get("title", ""),
        "specVersion": str(spec.get("info", {}).get("version", "")),
        "specSha256": spec_sha,
        "generator": GENERATOR_VERSION,
        "generatedFrom": source,
        "opCount": len(ops),
    }
    return {"meta": meta, "ops": ops}


def validate(catalogs: list[dict]) -> None:
    names: dict[str, str] = {}
    name_re = re.compile(r"^[a-z0-9_]{1,64}$")
    for cat in catalogs:
        fam = cat["meta"]["family"]
        for op in cat["ops"]:
            n = op["name"]
            if not name_re.match(n):
                raise CatalogError(f"invalid tool name {n!r}")
            if n in names:
                raise CatalogError(f"duplicate tool name {n} ({fam} and {names[n]})")
            names[n] = fam
            path_params = {p["name"] for p in op["params"] if p["in"] == "path"}
            templated = set(re.findall(r"\{([^{}]+)\}", op["path"]))
            missing = templated - path_params
            if missing:
                raise CatalogError(f"{n}: path placeholders without parameters: {sorted(missing)}")
            extra = path_params - templated
            if extra:
                raise CatalogError(f"{n}: path parameters not in template: {sorted(extra)}")
            for text in (op["summary"], op["description"]):
                if "<" in text or ">" in text:
                    raise CatalogError(f"{n}: markup survived in description")


def dumps(catalog: dict) -> str:
    return json.dumps(catalog, indent=1, ensure_ascii=False) + "\n"


def generate() -> dict[str, str]:
    outputs: dict[str, str] = {}
    catalogs = []
    for family, spec_file, out_file, prefix in FAMILIES:
        spec_path = SPEC_DIR / spec_file
        raw = spec_path.read_bytes()
        spec = json.loads(raw.decode("utf-8"))
        sha = hashlib.sha256(raw).hexdigest()
        cat = build_catalog(family, spec, prefix, sha, f"specs/{spec_file}")
        catalogs.append(cat)
        outputs[out_file] = dumps(cat)
    validate(catalogs)
    return outputs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify the committed catalog is up to date; exit 1 on drift")
    ap.add_argument("--out", type=Path, default=OUT_DIR, help="output directory (default: src/main/resources/catalog)")
    args = ap.parse_args(argv)

    outputs = generate()
    if args.check:
        drift = []
        for name, text in outputs.items():
            target = args.out / name
            current = target.read_text(encoding="utf-8") if target.exists() else None
            if current != text:
                drift.append(name)
        if drift:
            print(f"catalog out of date: {', '.join(drift)} — run: python tools/gen_catalog.py", file=sys.stderr)
            return 1
        print(f"catalog up to date ({', '.join(outputs)})")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        (args.out / name).write_text(text, encoding="utf-8", newline="\n")
        ops = json.loads(text)["meta"]["opCount"]
        print(f"wrote {args.out / name} ({ops} operations, {len(text.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
