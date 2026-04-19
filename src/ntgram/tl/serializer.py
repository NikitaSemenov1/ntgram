"""Schema-driven TL binary serializer / deserializer.

Supports the core TL type system: int, long, int128, int256, bytes/string, Bool,
flags (#), conditional fields (flags.N?T), Vector<T>, and recursive named types.
"""
from __future__ import annotations

import re
import struct
from typing import Any

from ntgram.tl.registry import ConstructorSpec, MethodSpec, TlSchemaRegistry

VECTOR_CONSTRUCTOR_ID = 0x1CB5C415
BOOL_TRUE_CONSTRUCTOR_ID = 0x997275B5
BOOL_FALSE_CONSTRUCTOR_ID = 0xBC799737

_CONDITIONAL_RE = re.compile(r"^(\w+)\.(\d+)\?(.+)$")


class TlSerializerError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Low-level reader
# ---------------------------------------------------------------------------

class _Reader:
    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes | memoryview) -> None:
        self._data = bytes(data) if isinstance(data, memoryview) else data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def _read(self, n: int) -> bytes:
        if self._offset + n > len(self._data):
            raise TlSerializerError(
                f"unexpected EOF: need {n} bytes at offset {self._offset}, "
                f"have {len(self._data) - self._offset}",
            )
        chunk = self._data[self._offset: self._offset + n]
        self._offset += n
        return chunk

    def read_int32(self) -> int:
        return struct.unpack("<i", self._read(4))[0]

    def read_uint32(self) -> int:
        return struct.unpack("<I", self._read(4))[0]

    def read_int64(self) -> int:
        return struct.unpack("<Q", self._read(8))[0]

    def read_int128(self) -> int:
        return int.from_bytes(self._read(16), "little")

    def read_int256(self) -> int:
        return int.from_bytes(self._read(32), "little")

    def read_bytes(self) -> bytes:
        first = self._read(1)[0]
        if first == 254:
            raw_len = self._read(3) + b"\x00"
            length = struct.unpack("<I", raw_len)[0]
            pad = (4 - ((length + 4) % 4)) % 4
        else:
            length = first
            pad = (4 - ((length + 1) % 4)) % 4
        value = self._read(length)
        if pad:
            self._read(pad)
        return value

    def read_string(self) -> str:
        return self.read_bytes().decode("utf-8")


# ---------------------------------------------------------------------------
# Low-level writer
# ---------------------------------------------------------------------------

def _write_int32(value: int) -> bytes:
    return struct.pack("<i", _as_signed_int32(value))


def _write_uint32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _write_int64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def _write_int128(value: int) -> bytes:
    return value.to_bytes(16, "little")


def _write_int256(value: int) -> bytes:
    return value.to_bytes(32, "little")


def _write_bytes(value: bytes) -> bytes:
    length = len(value)
    if length <= 253:
        prefix = bytes([length])
        padded = prefix + value
    else:
        prefix = bytes([254]) + struct.pack("<I", length)[:3]
        padded = prefix + value
    pad = (4 - (len(padded) % 4)) % 4
    return padded + (b"\x00" * pad)


def _write_string(value: str) -> bytes:
    return _write_bytes(value.encode("utf-8"))


def _as_signed_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        return value - 0x100000000
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def serialize_by_spec(
    spec: ConstructorSpec | MethodSpec,
    fields: dict[str, Any],
    registry: TlSchemaRegistry,
) -> bytes:
    """Serialize fields according to a TL spec (constructor or method).

    Returns bytes WITHOUT the leading constructor_id -- caller prepends it.
    """
    buf = bytearray()
    params = spec.params
    computed_flags: dict[str, int] = {}

    for pname, ptype in params:
        if ptype == "#":
            flag_val = _compute_flags(pname, params, fields)
            computed_flags[pname] = flag_val
            buf.extend(_write_uint32(flag_val))
            continue

        m = _CONDITIONAL_RE.match(ptype)
        if m:
            flag_field, bit_str, inner_type = m.group(1), int(m.group(2)), m.group(3)
            flag_val = computed_flags.get(flag_field, 0)
            if not (flag_val & (1 << bit_str)):
                continue
            if inner_type == "true":
                continue
            _serialize_value(buf, inner_type, fields.get(pname), registry)
        else:
            _serialize_value(buf, ptype, fields.get(pname), registry)

    return bytes(buf)


def deserialize_by_spec(
    spec: ConstructorSpec | MethodSpec,
    reader: _Reader,
    registry: TlSchemaRegistry,
) -> dict[str, Any]:
    """Deserialize fields according to a TL spec."""
    fields: dict[str, Any] = {}
    flags_store: dict[str, int] = {}

    for pname, ptype in spec.params:
        if ptype == "#":
            val = reader.read_uint32()
            flags_store[pname] = val
            fields[pname] = val
            continue

        m = _CONDITIONAL_RE.match(ptype)
        if m:
            flag_field, bit_num, inner_type = m.group(1), int(m.group(2)), m.group(3)
            flag_val = flags_store.get(flag_field, 0)
            if not (flag_val & (1 << bit_num)):
                continue
            if inner_type == "true":
                fields[pname] = True
                continue
            fields[pname] = _deserialize_value(inner_type, reader, registry)
        else:
            fields[pname] = _deserialize_value(ptype, reader, registry)

    return fields


def serialize_object(
    name: str,
    fields: dict[str, Any],
    registry: TlSchemaRegistry,
) -> bytes:
    """Serialize a TL object: constructor_id (4 bytes) + fields."""
    spec = registry.constructors_by_name.get(name)
    if spec is None:
        spec = registry.methods_by_name.get(name)
    if spec is None:
        raise TlSerializerError(f"unknown TL name: {name}")
    cid = _as_signed_int32(spec.id)
    return struct.pack("<i", cid) + serialize_by_spec(spec, fields, registry)


def deserialize_object(
    data: bytes,
    registry: TlSchemaRegistry,
    *,
    allow_method: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Deserialize a TL object from bytes. Returns (name, fields)."""
    reader = _Reader(data)
    name, fields = _deserialize_boxed(reader, registry, allow_method=allow_method)
    return name, fields


def deserialize_from_reader(
    reader: _Reader,
    registry: TlSchemaRegistry,
    *,
    allow_method: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Deserialize a TL object from an existing reader. Returns (name, fields)."""
    return _deserialize_boxed(reader, registry, allow_method=allow_method)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_flags(
    flag_field_name: str,
    params: tuple[tuple[str, str], ...],
    fields: dict[str, Any],
) -> int:
    """Compute the flags bitmask based on which conditional fields are present."""
    result = 0
    for pname, ptype in params:
        m = _CONDITIONAL_RE.match(ptype)
        if m and m.group(1) == flag_field_name:
            bit = int(m.group(2))
            inner = m.group(3)
            val = fields.get(pname)
            if inner == "true":
                if val:
                    result |= (1 << bit)
            elif val is not None:
                result |= (1 << bit)
    return result


def _serialize_value(
    buf: bytearray,
    tl_type: str,
    value: Any,
    registry: TlSchemaRegistry,
) -> None:
    if tl_type == "int":
        buf.extend(_write_int32(int(value) if value is not None else 0))
    elif tl_type == "long":
        buf.extend(_write_int64(int(value) if value is not None else 0))
    elif tl_type == "int128":
        buf.extend(_write_int128(int(value) if value is not None else 0))
    elif tl_type == "int256":
        buf.extend(_write_int256(int(value) if value is not None else 0))
    elif tl_type == "double":
        buf.extend(struct.pack("<d", float(value) if value is not None else 0.0))
    elif tl_type == "string":
        buf.extend(_write_string(str(value) if value is not None else ""))
    elif tl_type == "bytes":
        if isinstance(value, (bytes, bytearray, memoryview)):
            buf.extend(_write_bytes(bytes(value)))
        elif isinstance(value, str):
            buf.extend(_write_bytes(value.encode("utf-8")))
        else:
            buf.extend(_write_bytes(b""))
    elif tl_type == "Bool":
        cid = BOOL_TRUE_CONSTRUCTOR_ID if value else BOOL_FALSE_CONSTRUCTOR_ID
        buf.extend(_write_int32(cid))
    elif tl_type == "Object":
        if isinstance(value, bytes):
            buf.extend(value)
        elif isinstance(value, dict):
            name = value.get("_constructor") or value.get("constructor")
            if name is not None:
                inner_fields = {
                    k: v for k, v in value.items()
                    if k not in ("_constructor", "constructor")
                }
                try:
                    buf.extend(serialize_object(name, inner_fields, registry))
                except TlSerializerError:
                    _serialize_generic_object(buf, value)
            else:
                _serialize_generic_object(buf, value)
        else:
            raise TlSerializerError(f"cannot serialize Object from {type(value)}")
    elif tl_type.startswith("Vector<") or tl_type.startswith("vector<"):
        inner = tl_type[7:-1]
        items = value if isinstance(value, list) else []
        bare = tl_type[0] == "v"
        if not bare:
            buf.extend(_write_int32(VECTOR_CONSTRUCTOR_ID))
        buf.extend(_write_int32(len(items)))
        for item in items:
            _serialize_value(buf, inner, item, registry)
    else:
        if isinstance(value, dict):
            name = value.get("_constructor") or value.get("constructor") or tl_type
            inner_fields = {k: v for k, v in value.items() if k not in ("_constructor", "constructor")}
            buf.extend(serialize_object(name, inner_fields, registry))
        elif isinstance(value, bytes):
            buf.extend(value)
        else:
            raise TlSerializerError(f"unsupported TL type {tl_type!r} for value {value!r}")


GENERIC_OBJECT_CONSTRUCTOR_ID = 0x7F010099


def _serialize_generic_object(buf: bytearray, value: dict) -> None:
    """Fallback: serialize a dict without a known TL constructor as a generic
    wrapper (synthetic constructor_id + JSON bytes). Used for business logic
    results not yet mapped to proper TL types."""
    import json as _json
    buf.extend(_write_int32(GENERIC_OBJECT_CONSTRUCTOR_ID))
    buf.extend(_write_bytes(_json.dumps(value, ensure_ascii=False).encode("utf-8")))


def _deserialize_value(
    tl_type: str,
    reader: _Reader,
    registry: TlSchemaRegistry,
) -> Any:
    if tl_type == "int":
        return reader.read_int32()
    if tl_type == "long":
        return reader.read_int64()
    if tl_type == "int128":
        return reader.read_int128()
    if tl_type == "int256":
        return reader.read_int256()
    if tl_type == "double":
        return struct.unpack("<d", reader._read(8))[0]
    if tl_type == "string":
        return reader.read_string()
    if tl_type == "bytes":
        return reader.read_bytes()
    if tl_type == "Bool":
        cid = reader.read_int32()
        if cid == _as_signed_int32(BOOL_TRUE_CONSTRUCTOR_ID):
            return True
        if cid == _as_signed_int32(BOOL_FALSE_CONSTRUCTOR_ID):
            return False
        raise TlSerializerError(f"invalid Bool constructor: {cid:#010x}")
    if tl_type == "Object":
        peek_cid = struct.unpack("<i", reader._data[reader._offset: reader._offset + 4])[0]
        if peek_cid == _as_signed_int32(GENERIC_OBJECT_CONSTRUCTOR_ID):
            reader._offset += 4
            raw = reader.read_bytes()
            import json as _json
            return _json.loads(raw)
        name, fields = _deserialize_boxed(reader, registry)
        fields["_constructor"] = name
        return fields
    if tl_type.startswith("Vector<") or tl_type.startswith("vector<"):
        inner = tl_type[7:-1]
        bare = tl_type[0] == "v"
        if not bare:
            vec_cid = reader.read_int32()
            if vec_cid != _as_signed_int32(VECTOR_CONSTRUCTOR_ID):
                raise TlSerializerError(f"expected vector cid, got {vec_cid:#010x}")
        count = reader.read_int32()
        return [_deserialize_value(inner, reader, registry) for _ in range(count)]

    # Named type -- read boxed constructor
    name, fields = _deserialize_boxed(reader, registry)
    fields["_constructor"] = name
    return fields


def _deserialize_boxed(
    reader: _Reader,
    registry: TlSchemaRegistry,
    *,
    allow_method: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Read a constructor_id and deserialize by spec."""
    cid = reader.read_int32()

    spec = registry.constructors_by_id.get(cid)
    if spec is not None:
        name = spec.predicate
        fields = deserialize_by_spec(spec, reader, registry)
        return name, fields

    if allow_method:
        mspec = registry.methods_by_id.get(cid)
        if mspec is not None:
            name = mspec.method
            fields = deserialize_by_spec(mspec, reader, registry)
            return name, fields

    raise TlSerializerError(f"unknown constructor id: {cid:#010x}")
