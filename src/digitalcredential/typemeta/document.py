from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from digitalcredential.typemeta.errors import ErrInvalid


@dataclass
class Image:
    uri: str = ""
    uri_integrity: str | None = None
    alt_text: str = ""


@dataclass
class SimpleRendering:
    logo: Image | None = None
    background_image: Image | None = None
    background_color: str = ""
    text_color: str = ""


@dataclass
class SVGProperties:
    orientation: str = ""
    color_scheme: str = ""
    contrast: str = ""


@dataclass
class SVGTemplate:
    uri: str = ""
    uri_integrity: str | None = None
    properties: SVGProperties | None = None


@dataclass
class Rendering:
    simple: SimpleRendering | None = None
    svg_templates: list[SVGTemplate] = field(default_factory=list)


@dataclass
class Display:
    locale: str = ""
    name: str = ""
    description: str = ""
    rendering: Rendering | None = None


@dataclass
class ClaimDisplay:
    locale: str = ""
    label: str = ""
    description: str = ""


@dataclass
class Claim:
    path: list[Any] = field(default_factory=list)
    display: list[ClaimDisplay] = field(default_factory=list)
    mandatory: bool = False
    sd: str = "allowed"
    svg_id: str = ""


@dataclass
class Document:
    vct: str = ""
    name: str = ""
    description: str = ""
    extends: str = ""
    extends_integrity: str = ""
    display: list[Display] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)

    def encode(self) -> Encoded:
        payload = {
            "vct": self.vct,
            **({"name": self.name} if self.name else {}),
            **({"description": self.description} if self.description else {}),
            **({"extends": self.extends} if self.extends else {}),
            **({"extends#integrity": self.extends_integrity} if self.extends_integrity else {}),
        }
        if self.display:
            payload["display"] = [_display_to_json(d) for d in self.display]
        if self.claims:
            payload["claims"] = [_claim_to_json(c) for c in self.claims]
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        from digitalcredential.typemeta.format import parse_encoded_bytes

        return parse_encoded_bytes(raw)


@dataclass
class Encoded:
    vct: str
    bytes: bytes

    def integrity(self) -> str:
        from digitalcredential.typemeta.integrity import integrity

        return integrity(self.bytes)


def parse_encoded(doc: bytes) -> Encoded:
    from digitalcredential.typemeta.format import parse_encoded_bytes

    return parse_encoded_bytes(bytes(doc))


def _display_to_json(d: Display) -> dict[str, Any]:
    out: dict[str, Any] = {"locale": d.locale, "name": d.name}
    if d.description:
        out["description"] = d.description
    if d.rendering:
        out["rendering"] = _rendering_to_json(d.rendering)
    return out


def _rendering_to_json(r: Rendering) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if r.simple:
        s = r.simple
        sm: dict[str, Any] = {}
        if s.logo:
            sm["logo"] = _image_to_json(s.logo, logo=True)
        if s.background_image:
            sm["background_image"] = _image_to_json(s.background_image, logo=False)
        if s.background_color:
            sm["background_color"] = s.background_color
        if s.text_color:
            sm["text_color"] = s.text_color
        out["simple"] = sm
    if r.svg_templates:
        out["svg_templates"] = [_svg_to_json(t) for t in r.svg_templates]
    return out


def _image_to_json(img: Image, logo: bool) -> dict[str, Any]:
    out: dict[str, Any] = {"uri": img.uri}
    if img.uri_integrity is not None:
        out["uri#integrity"] = img.uri_integrity
    if logo and img.alt_text:
        out["alt_text"] = img.alt_text
    return out


def _svg_to_json(t: SVGTemplate) -> dict[str, Any]:
    out: dict[str, Any] = {"uri": t.uri}
    if t.uri_integrity is not None:
        out["uri#integrity"] = t.uri_integrity
    if t.properties:
        p = t.properties
        props = {k: v for k, v in (("orientation", p.orientation), ("color_scheme", p.color_scheme), ("contrast", p.contrast)) if v}
        if props:
            out["properties"] = props
    return out


def _claim_to_json(c: Claim) -> dict[str, Any]:
    out: dict[str, Any] = {"path": c.path}
    if c.display:
        out["display"] = [{"locale": d.locale, "label": d.label, **({"description": d.description} if d.description else {})} for d in c.display]
    if c.mandatory:
        out["mandatory"] = True
    if c.sd and c.sd != "allowed":
        out["sd"] = c.sd
    if c.svg_id:
        out["svg_id"] = c.svg_id
    return out


def document_from_parsed(d) -> Document:
    doc = Document(vct=d.vct, name=d.name, description=d.description)
    if d.has_extends:
        doc.extends = d.extends
    if d.has_extends_integrity:
        doc.extends_integrity = d.extends_integrity
    doc.display = d.display or []
    claims, _ = d.read_claims()
    doc.claims = [cm.claim for cm in claims] if claims else []
    return doc
