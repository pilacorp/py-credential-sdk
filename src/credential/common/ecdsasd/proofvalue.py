from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import cbor2

from credential.common.util.b64 import b64url_decode

BASE_PROOF_HEADER = bytes([0xD9, 0x5D, 0x00])
DERIVED_PROOF_HEADER = bytes([0xD9, 0x5D, 0x01])


@dataclass
class SpecBaseProof:
    base_signature: bytes
    public_key: bytes
    hmac_key: bytes
    signatures: list[bytes]
    mandatory_pointers: list[str] = field(default_factory=list)


@dataclass
class SpecDerivedProof:
    base_signature: bytes
    public_key: bytes
    signatures: list[bytes]
    label_map: dict[str, str]
    mandatory_indexes: list[int]


def _cbor_det_dump(obj: Any) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def serialize_base_proof_value(proof: SpecBaseProof) -> str:
    mandatory = proof.mandatory_pointers if proof.mandatory_pointers is not None else []
    payload = [
        proof.base_signature,
        proof.public_key,
        proof.hmac_key,
        proof.signatures,
        mandatory,
    ]
    enc = _cbor_det_dump(payload)
    return multibase_proof_value(BASE_PROOF_HEADER, enc)


def _loads_strict(raw: bytes) -> Any:
    """cbor2.loads that, like Go's cbor.Unmarshal, rejects trailing bytes."""
    import io

    buf = io.BytesIO(raw)
    try:
        value = cbor2.CBORDecoder(buf).decode()
    except Exception as exc:
        raise ValueError(f"ecdsasd: cbor unmarshal: {exc}") from exc
    if buf.read(1):
        raise ValueError("ecdsasd: cbor unmarshal: extraneous data after the proof value")
    return value


def _array_or_null(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"ecdsasd: {what} must be an array")
    return value


def parse_base_proof_value(proof_value: str) -> SpecBaseProof:
    raw = decode_proof_value(proof_value, BASE_PROOF_HEADER)
    arr = _loads_strict(raw)
    if not isinstance(arr, list) or len(arr) != 5:
        raise ValueError(f"ecdsasd: base proof value: want 5 elements, got {len(arr) if isinstance(arr, list) else type(arr)!r}")
    pointers = _array_or_null(arr[4], "mandatory pointers")
    if not all(isinstance(x, str) for x in pointers):
        raise ValueError("ecdsasd: mandatory pointers must be strings")
    return SpecBaseProof(
        base_signature=_as_bytes(arr[0]),
        public_key=_as_bytes(arr[1]),
        hmac_key=_as_bytes(arr[2]),
        signatures=[_as_bytes(x) for x in _array_or_null(arr[3], "signatures")],
        mandatory_pointers=list(pointers),
    )


def serialize_disclosure_proof_value(proof: SpecDerivedProof) -> str:
    compressed = compress_label_map(proof.label_map)
    m_idx = [int(n) for n in proof.mandatory_indexes]
    # Go's nil slice (no revealed non-mandatory statement) encodes as CBOR null; keep issuance byte-identical.
    sigs = proof.signatures if proof.signatures else None
    payload = [proof.base_signature, proof.public_key, sigs, compressed, m_idx]
    enc = _cbor_det_dump(payload)
    return multibase_proof_value(DERIVED_PROOF_HEADER, enc)


def parse_disclosure_proof_value(proof_value: str) -> SpecDerivedProof:
    raw = decode_proof_value(proof_value, DERIVED_PROOF_HEADER)
    arr = _loads_strict(raw)
    if not isinstance(arr, list) or len(arr) != 5:
        raise ValueError(
            f"ecdsasd: derived proof value: want 5 elements, got {len(arr) if isinstance(arr, list) else type(arr)!r}"
        )
    compressed = arr[3]
    if compressed is None:
        compressed = {}
    if not isinstance(compressed, dict):
        raise ValueError("ecdsasd: derived proof label map must be a map")
    if not all(isinstance(k, int) and not isinstance(k, bool) and k >= 0 for k in compressed):
        raise ValueError("ecdsasd: derived proof label map keys must be unsigned integers")
    label_map = decompress_label_map({k: _as_bytes(v) for k, v in compressed.items()})
    m_idx = _array_or_null(arr[4], "mandatory indexes")
    if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in m_idx):
        raise ValueError("ecdsasd: mandatory indexes must be unsigned integers")
    return SpecDerivedProof(
        base_signature=_as_bytes(arr[0]),
        public_key=_as_bytes(arr[1]),
        signatures=[_as_bytes(x) for x in _array_or_null(arr[2], "signatures")],
        label_map=label_map,
        mandatory_indexes=list(m_idx),
    )


def compress_label_map(label_map: dict[str, str]) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    for k, v in label_map.items():
        if not k.startswith("c14n"):
            raise ValueError(f"ecdsasd: label map key {k!r}")
        try:
            num = int(k[4:])
            if num < 0:
                raise ValueError("negative")
            out[num] = b64url_decode(v[1:] if v.startswith("u") else v)
        except ValueError as exc:
            raise ValueError(f"ecdsasd: label map entry {k!r}: {exc}") from exc
    return out


def decompress_label_map(compressed: dict[int, bytes]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k in sorted(compressed.keys()):
        out[f"c14n{k}"] = "u" + base64.urlsafe_b64encode(compressed[k]).decode("ascii").rstrip("=")
    return out


def multibase_proof_value(header: bytes, payload: bytes) -> str:
    buf = header + payload
    return "u" + base64.urlsafe_b64encode(buf).decode("ascii").rstrip("=")


def decode_proof_value(proof_value: str, header: bytes) -> bytes:
    if not proof_value or proof_value[0] != "u":
        raise ValueError("ecdsasd: proof value must be base64url-no-pad multibase ('u')")
    try:
        raw = b64url_decode(proof_value[1:])
    except ValueError as exc:
        raise ValueError(f"ecdsasd: decode proof value: {exc}") from exc
    if not raw.startswith(header):
        raise ValueError("ecdsasd: proof value has wrong header")
    return raw[len(header) :]


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    raise ValueError(f"ecdsasd: expected bytes, got {type(value)!r}")
