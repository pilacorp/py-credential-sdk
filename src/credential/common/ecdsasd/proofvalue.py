from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import cbor2

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


def parse_base_proof_value(proof_value: str) -> SpecBaseProof:
    raw = decode_proof_value(proof_value, BASE_PROOF_HEADER)
    arr = cbor2.loads(raw)
    if not isinstance(arr, list) or len(arr) != 5:
        raise ValueError(f"ecdsasd: base proof value: want 5 elements, got {len(arr) if isinstance(arr, list) else type(arr)!r}")
    return SpecBaseProof(
        base_signature=_as_bytes(arr[0]),
        public_key=_as_bytes(arr[1]),
        hmac_key=_as_bytes(arr[2]),
        signatures=[_as_bytes(x) for x in arr[3]],
        mandatory_pointers=[str(x) for x in arr[4]],
    )


def serialize_disclosure_proof_value(proof: SpecDerivedProof) -> str:
    compressed = compress_label_map(proof.label_map)
    m_idx = [int(n) for n in proof.mandatory_indexes]
    payload = [proof.base_signature, proof.public_key, proof.signatures, compressed, m_idx]
    enc = _cbor_det_dump(payload)
    return multibase_proof_value(DERIVED_PROOF_HEADER, enc)


def parse_disclosure_proof_value(proof_value: str) -> SpecDerivedProof:
    raw = decode_proof_value(proof_value, DERIVED_PROOF_HEADER)
    arr = cbor2.loads(raw)
    if not isinstance(arr, list) or len(arr) != 5:
        raise ValueError(
            f"ecdsasd: derived proof value: want 5 elements, got {len(arr) if isinstance(arr, list) else type(arr)!r}"
        )
    compressed = arr[3]
    if not isinstance(compressed, dict):
        raise ValueError("ecdsasd: derived proof label map must be a map")
    label_map = decompress_label_map({int(k): _as_bytes(v) for k, v in compressed.items()})
    m_idx_raw = arr[4]
    mandatory_indexes = [int(x) for x in m_idx_raw]
    return SpecDerivedProof(
        base_signature=_as_bytes(arr[0]),
        public_key=_as_bytes(arr[1]),
        signatures=[_as_bytes(x) for x in arr[2]],
        label_map=label_map,
        mandatory_indexes=mandatory_indexes,
    )


def compress_label_map(label_map: dict[str, str]) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    for k, v in label_map.items():
        if not k.startswith("c14n"):
            raise ValueError(f"ecdsasd: label map key {k!r}")
        num = int(k[4:])
        vb = v[1:] if v.startswith("u") else v
        pad = "=" * ((4 - len(vb) % 4) % 4)
        out[num] = base64.urlsafe_b64decode(vb + pad)
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
    pad = "=" * ((4 - (len(proof_value) - 1) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(proof_value[1:] + pad)
    except Exception as exc:
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
