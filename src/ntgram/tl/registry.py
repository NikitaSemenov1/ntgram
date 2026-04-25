from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True, frozen=True)
class ConstructorSpec:
    predicate: str
    id: int
    params: tuple[tuple[str, str], ...] = ()
    result_type: str = ""


@dataclass(slots=True, frozen=True)
class MethodSpec:
    method: str
    id: int
    params: tuple[tuple[str, str], ...]
    result_type: str


@dataclass(slots=True, frozen=True)
class TlSchemaRegistry:
    constructors_by_name: dict[str, ConstructorSpec]
    constructors_by_id: dict[int, ConstructorSpec]
    methods_by_name: dict[str, MethodSpec]
    methods_by_id: dict[int, MethodSpec]

    def method_name_by_id(self, method_id: int) -> str | None:
        method = self.methods_by_id.get(method_id)
        return method.method if method else None

    def constructor_name_by_id(self, constructor_id: int) -> str | None:
        constructor = self.constructors_by_id.get(constructor_id)
        return constructor.predicate if constructor else None

    def get_spec_by_name(self, name: str) -> ConstructorSpec | MethodSpec | None:
        if name in self.methods_by_name:
            return self.methods_by_name[name]
        if name in self.constructors_by_name:
            return self.constructors_by_name[name]
        return None

    def get_spec_by_id(self, spec_id: int) -> ConstructorSpec | MethodSpec | None:
        if spec_id in self.methods_by_id:
            return self.methods_by_id[spec_id]
        if spec_id in self.constructors_by_id:
            return self.constructors_by_id[spec_id]
        return None


def _normalize_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


def _parse_int32(raw: Any) -> int:
    if isinstance(raw, str):
        return _normalize_int32(int(raw, 10))
    if isinstance(raw, int):
        return _normalize_int32(raw)
    raise ValueError(f"invalid int32 field: {raw!r}")


def load_schema_registry(base_dir: Path) -> TlSchemaRegistry:
    """Load constructor names from api/mtproto JSON schemas.

    The runtime router remains hardcoded by design. This loader provides constructor and method IDs
    from schema sources to reduce mismatch risk and remove magic constants in transport payloads.
    """
    constructors_by_name: dict[str, ConstructorSpec] = {}
    constructors_by_id: dict[int, ConstructorSpec] = {}
    methods_by_name: dict[str, MethodSpec] = {}
    methods_by_id: dict[int, MethodSpec] = {}

    for file_name in ("mtproto.json", "api.json"):
        path = base_dir / file_name
        if not path.exists():
            continue

        data = json.loads(path.read_text(encoding="utf-8"))
        for constructor in data.get("constructors", []):
            predicate = constructor.get("predicate")
            raw_id = constructor.get("id")
            if isinstance(predicate, str):
                constructor_id = _parse_int32(raw_id)
                params = constructor.get("params", [])
                typed_params: list[tuple[str, str]] = []
                for param in params:
                    pname = param.get("name")
                    ptype = param.get("type")
                    if isinstance(pname, str) and isinstance(ptype, str):
                        typed_params.append((pname, ptype))
                spec = ConstructorSpec(
                    predicate=predicate,
                    id=constructor_id,
                    params=tuple(typed_params),
                    result_type=str(constructor.get("type", "")),
                )
                constructors_by_name[predicate] = spec
                constructors_by_id[constructor_id] = spec

        for method in data.get("methods", []):
            method_name = method.get("method")
            raw_id = method.get("id")
            if not isinstance(method_name, str):
                continue

            method_id = _parse_int32(raw_id)
            params = method.get("params", [])
            typed_params: list[tuple[str, str]] = []
            for param in params:
                name = param.get("name")
                type_name = param.get("type")
                if isinstance(name, str) and isinstance(type_name, str):
                    typed_params.append((name, type_name))

            spec = MethodSpec(
                method=method_name,
                id=method_id,
                params=tuple(typed_params),
                result_type=str(method.get("type", "Object")),
            )
            methods_by_name[method_name] = spec
            methods_by_id[method_id] = spec

    return TlSchemaRegistry(
        constructors_by_name=constructors_by_name,
        constructors_by_id=constructors_by_id,
        methods_by_name=methods_by_name,
        methods_by_id=methods_by_id,
    )


def default_schema_registry() -> TlSchemaRegistry:
    candidates: list[Path] = []
    env_path = os.getenv("NTGRAM_TL_SCHEMA_DIR")
    if env_path:
        candidates.append(Path(env_path))

    module_path = Path(__file__).resolve()
    # Canonical runtime schemas: ntgram/tl (sibling of src/ in the ntgram repo).
    repo_tl = module_path.parents[3] / "tl"
    candidates.extend(
        [
            repo_tl,
            module_path.parents[3] / "docs" / "knowledge" / "mtproto",
            Path.cwd() / "tl",
            Path.cwd() / "docs" / "knowledge" / "mtproto",
            Path("/app/tl"),
            Path("/app/docs/knowledge/mtproto"),
        ],
    )

    for base_dir in candidates:
        if not base_dir.exists():
            continue
        registry = load_schema_registry(base_dir)
        if registry.methods_by_id or registry.constructors_by_id:
            return registry

    searched = ", ".join(str(path) for path in candidates)
    raise RuntimeError(f"TL schema registry is empty; searched: {searched}")
