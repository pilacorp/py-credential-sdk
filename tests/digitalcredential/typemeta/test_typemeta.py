from pathlib import Path

import hashlib
import base64

from digitalcredential.typemeta import CheckIntegrity, ErrInvalid, Integrity, Load, Ref, Static, parse_encoded
from digitalcredential.typemeta.document import parse_encoded as parse_encoded_fn

VCT42 = "https://betelgeuse.example.com/education_credential/v42"
FIG30 = Path(__file__).parent / "testdata" / "figure30.json"


def _fig30_sha256() -> str:
    data = FIG30.read_bytes()
    digest = hashlib.sha256(data).digest()
    return "sha256-" + base64.standard_b64encode(digest).decode("ascii")


def test_figure30_load() -> None:
    doc = FIG30.read_bytes()
    integrity = _fig30_sha256()
    assert Integrity(doc) == integrity
    CheckIntegrity(doc, integrity)
    m = Load(Static(doc), Ref(vct=VCT42, integrity=integrity))
    claims = m.claims_list()
    assert len(claims) == 7
    assert claims[4].path == ["degrees", None]
    assert claims[4].sd == "always"
    assert claims[4].mandatory is False
    assert claims[0].mandatory and claims[0].sd == "always"
    assert len(claims[0].display) == 2 and claims[0].display[1].label == "Name"
    assert claims[2].svg_id == "address_street_address"
    display = m.display_list()
    assert len(display) == 2
    assert display[1].locale == "de-DE"
    assert display[0].rendering and display[0].rendering.simple
    assert display[0].rendering.simple.background_color == "#12107c"
    svg = display[0].rendering.svg_templates[0]
    assert svg.properties and svg.properties.orientation == "landscape"
    assert m.documents()[0] == doc
    enc = parse_encoded_fn(doc)
    assert enc.integrity() == integrity


def test_parse_encoded_rejects_empty_vct() -> None:
    try:
        parse_encoded(b'{"name":"x"}')
        raise AssertionError("expected error")
    except ErrInvalid:
        pass
