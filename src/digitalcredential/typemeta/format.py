from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from digitalcredential.internal import jsonint, sri, uri
from digitalcredential.internal.safehttp import https_url
from jose import json as jose_json
from jose.json import JsonNumber
from digitalcredential.typemeta.color import rgb_color
from digitalcredential.typemeta.document import (
    Claim,
    ClaimDisplay,
    Display,
    Encoded,
    Image,
    Rendering,
    SVGProperties,
    SVGTemplate,
    SimpleRendering,
)
from digitalcredential.typemeta.errors import ErrClaims, ErrInvalid
from digitalcredential.typemeta.langtag import well_formed_lang_tag

MAX_DOCUMENT_BYTES = 256 << 10
MAX_CHAIN = 8
MAX_CLAIMS = 1000
MAX_PATH = 64
MAX_DISPLAY = 100

SD_ALWAYS = "always"
SD_ALLOWED = "allowed"
SD_NEVER = "never"


@dataclass
class _Document:
    vct: str = ""
    name: str = ""
    description: str = ""
    extends: str = ""
    extends_integrity: str = ""
    has_extends: bool = False
    has_extends_integrity: bool = False
    display: list[Display] = field(default_factory=list)
    has_display: bool = False
    claims_raw: Any = None
    has_claims: bool = False


@dataclass
class _ClaimMeta:
    claim: Claim
    has_display: bool = False
    has_mandatory: bool = False
    has_sd: bool = False
    has_svg_id: bool = False


def read_document(raw: bytes) -> _Document:
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise _invalid(f"the document is over {MAX_DOCUMENT_BYTES} bytes, the SDK's limit")
    try:
        obj = jose_json.decode_json(raw)
    except Exception as exc:  # jose.ErrMalformed: duplicate keys, bad UTF-8, depth, trailing data
        raise ErrInvalid(f"typemeta: {exc}") from exc
    if not isinstance(obj, dict):
        raise _invalid("the document is not a JSON object (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
    d = _Document()
    vct = obj.get("vct")
    if not isinstance(vct, str):
        raise _invalid("vct is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
    d.vct = vct
    if "name" in obj and not isinstance(obj["name"], str):
        raise _invalid("name or description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
    d.name = obj.get("name") or ""
    if "description" in obj and not isinstance(obj["description"], str):
        raise _invalid("name or description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.2)")
    d.description = obj.get("description") or ""
    d.has_extends = "extends" in obj
    if d.has_extends:
        ext = obj.get("extends")
        if not isinstance(ext, str) or not ext:
            raise _invalid("extends is not a non-empty string; it names the type extended (draft-ietf-oauth-sd-jwt-vc-19 §5.4)")
        d.extends = ext
    d.has_extends_integrity = "extends#integrity" in obj
    if "extends#integrity" in obj:
        if not isinstance(obj["extends#integrity"], str):
            raise _invalid("extends#integrity is not a string (draft-ietf-oauth-sd-jwt-vc-19 §6)")
        d.extends_integrity = obj["extends#integrity"]
    if d.has_extends_integrity and not sri.well_formed(d.extends_integrity):
        raise _invalid(
            "extends#integrity is not integrity metadata (sha256-, sha384- or sha512- and base64, "
            "tokens separated by spaces; W3C SRI §3.5, draft-ietf-oauth-sd-jwt-vc-19 §6)"
        )
    if d.has_extends_integrity and not d.extends_integrity.strip():
        raise _invalid(
            "extends#integrity is present and holds no hash, so none can check the parent document"
        )
    if "display" in obj:
        d.has_display = True
        d.display = _read_displays(obj["display"])
    if "claims" in obj:
        d.has_claims = True
        d.claims_raw = obj["claims"]
    return d


def parse_encoded_bytes(b: bytes) -> Encoded:
    d = read_document(b)
    if not d.vct:
        raise ErrInvalid("typemeta: vct is empty")
    if not d.has_extends and d.has_extends_integrity:
        raise ErrInvalid("typemeta: extends#integrity without extends (draft-ietf-oauth-sd-jwt-vc-19 §6)")
    claims, err = d.read_claims()
    if err:
        raise err
    if claims:
        svg_err = _check_svg_ids(claims)
        if svg_err:
            raise svg_err
    return Encoded(vct=d.vct, bytes=b)


def _read_displays(v: Any) -> list[Display]:
    if not isinstance(v, list):
        raise _invalid("display is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.5)")
    if len(v) > MAX_DISPLAY:
        raise _invalid(f"display has over {MAX_DISPLAY} elements, the SDK's limit")
    out: list[Display] = []
    for i, e in enumerate(v):
        if not isinstance(e, dict):
            raise _invalid(f"display[{i}] is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5)")
        at = f"display[{i}]"
        loc = e.get("locale")
        if not isinstance(loc, str) or not well_formed_lang_tag(loc):
            raise _invalid(f"{at}.locale is absent or not a well-formed language tag")
        name = e.get("name")
        if not isinstance(name, str):
            raise _invalid(f"{at}.name is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5)")
        desc = e.get("description", "")
        if "description" in e and not isinstance(desc, str):
            raise _invalid(f"{at}.description is not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5)")
        disp = Display(locale=loc, name=name, description=desc or "")
        if "rendering" in e:
            disp.rendering = _read_rendering(e["rendering"], f"{at}.rendering")
        out.append(disp)
    return out


def _read_rendering(v: Any, at: str) -> Rendering:
    if not isinstance(v, dict):
        raise _invalid(f"{at} is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1)")
    r = Rendering()
    if "simple" in v:
        sm = v["simple"]
        if not isinstance(sm, dict):
            raise _invalid(f"{at}.simple is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.1)")
        simple = SimpleRendering()
        simple.logo = _read_image(sm, "logo", f"{at}.simple", logo=True)
        simple.background_image = _read_image(sm, "background_image", f"{at}.simple", logo=False)
        for key, dst in (("background_color", "background_color"), ("text_color", "text_color")):
            if key in sm:
                val = sm[key]
                if not isinstance(val, str) or not rgb_color(val):
                    raise _invalid(f"{at}.simple.{key} is not an RGB color value")
                setattr(simple, dst, val)
        r.simple = simple
    if "svg_templates" in v:
        arr = v["svg_templates"]
        if not isinstance(arr, list):
            raise _invalid(f"{at}.svg_templates is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2)")
        r.svg_templates = [_read_svg_template(e, len(arr) > 1, f"{at}.svg_templates[{i}]") for i, e in enumerate(arr)]
    return r


def _read_image(m: dict[str, Any], name: str, at: str, logo: bool) -> Image | None:
    if name not in m:
        return None
    im = m[name]
    if not isinstance(im, dict):
        raise _invalid(f"{at}.{name} is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.1)")
    at = f"{at}.{name}"
    uri_s = _read_uri(im, at)
    img = Image(uri=uri_s)
    if logo and "alt_text" in im and not isinstance(im["alt_text"], str):
        raise _invalid(f"{at}.alt_text is not a string")
    if logo:
        img.alt_text = im.get("alt_text") or ""
    if "uri#integrity" in im:
        ui = im["uri#integrity"]
        if not isinstance(ui, str):
            raise _invalid(f"{at}.uri#integrity is not a string")
        if ui and not sri.well_formed(ui):
            raise _invalid(f"{at}.uri#integrity is not integrity metadata")
        img.uri_integrity = ui
    return img


def _read_svg_template(v: Any, several: bool, at: str) -> SVGTemplate:
    if not isinstance(v, dict):
        raise _invalid(f"{at} is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1.2)")
    t = SVGTemplate(uri=_read_uri(v, at))
    if "uri#integrity" in v:
        ui = v["uri#integrity"]
        if not isinstance(ui, str):
            raise _invalid(f"{at}.uri#integrity is not a string")
        if ui and not sri.well_formed(ui):
            raise _invalid(f"{at}.uri#integrity is not integrity metadata")
        t.uri_integrity = ui
    if "properties" not in v:
        if several:
            raise _invalid(f"{at} has no properties, which is required when there is more than one template")
        return t
    pm = v["properties"]
    if not isinstance(pm, dict):
        raise _invalid(f"{at}.properties is not an object")
    props = SVGProperties()
    for key, vals in (
        ("orientation", ("portrait", "landscape")),
        ("color_scheme", ("light", "dark")),
        ("contrast", ("normal", "high")),
    ):
        if key in pm:
            s = pm[key]
            if s not in vals:
                raise _invalid(f"{at}.properties.{key} is neither {vals[0]} nor {vals[1]}")
            setattr(props, key if key != "color_scheme" else "color_scheme", s)
    if not (props.orientation or props.color_scheme or props.contrast):
        raise _invalid(f"{at}.properties has none of orientation, color_scheme and contrast")
    t.properties = props
    return t


def _read_uri(m: dict[str, Any], at: str) -> str:
    s = m.get("uri")
    if not isinstance(s, str):
        raise _invalid(f"{at}.uri is absent or not a string (draft-ietf-oauth-sd-jwt-vc-19 §5.5.1)")
    # url.Parse accepts more than RFC 3986, such as a host in Unicode; uri.valid does not.
    if uri.valid(s):
        if https_url(s):
            return s
        # RFC 2397 §3: data:[<mediatype>][;base64],<data>; the comma is required, and data is *uric
        # (EID 2045). url.Parse puts it in Opaque: what follows "data:" up to "?" or "#", when it does
        # not start with "/".
        scheme, _, rest = s.partition(":")
        opaque = rest.partition("#")[0].partition("?")[0]
        if scheme.lower() == "data" and not rest.startswith("/") and "," in opaque:
            return s
    raise _invalid(f"{at}.uri is neither an https URL with a host nor a data: URI")


def _Document_read_claims(self: _Document) -> tuple[list[_ClaimMeta] | None, Exception | None]:
    if not self.has_claims:
        return None, None
    if self.claims_raw is None:
        return None, _claims_err("claims is null")
    if not isinstance(self.claims_raw, list):
        return None, _claims_err("claims is not an array (draft-ietf-oauth-sd-jwt-vc-19 §5.6)")
    if len(self.claims_raw) > MAX_CLAIMS:
        return None, _claims_err(f"claims has over {MAX_CLAIMS} elements, the SDK's limit")
    out: list[_ClaimMeta] = []
    for i, e in enumerate(self.claims_raw):
        try:
            out.append(_read_claim(e, f"claims[{i}]"))
        except ErrClaims as exc:
            return None, exc
    return out, None


_Document.read_claims = _Document_read_claims  # type: ignore[method-assign]


def _read_claim(v: Any, at: str) -> _ClaimMeta:
    if not isinstance(v, dict):
        raise _claims_err(f"{at} is not an object (draft-ietf-oauth-sd-jwt-vc-19 §5.6)")
    path = v.get("path")
    if not isinstance(path, list) or not path:
        raise _claims_err(f"{at}.path is absent or not a non-empty array (draft-ietf-oauth-sd-jwt-vc-19 §5.6.1)")
    if len(path) > MAX_PATH:
        raise _claims_err(f"{at}.path has over {MAX_PATH} elements, the SDK's limit")
    norm_path: list[Any] = []
    for i, el in enumerate(path):
        if isinstance(el, str) or el is None:
            norm_path.append(el)
        elif isinstance(el, JsonNumber):
            # A non-negative integer is a value (RFC 8259 §6): 1, 1.0 and 1e0 select the same element.
            try:
                norm_path.append(jsonint.non_negative(str(el)))
            except ValueError as exc:
                raise _claims_err(
                    f"{at}.path[{i}] is a number that is not a non-negative integer an int holds "
                    "(draft-ietf-oauth-sd-jwt-vc-19 §5.6.1)"
                ) from exc
        else:
            raise _claims_err(f"{at}.path[{i}] is not a string, null or a non-negative integer")
    c = Claim(path=norm_path)
    meta = _ClaimMeta(claim=c)
    if "display" in v:
        meta.has_display = True
        arr = v["display"]
        if not isinstance(arr, list):
            raise _claims_err(f"{at}.display is not an array")
        if len(arr) > MAX_DISPLAY:
            raise _claims_err(f"{at}.display has over {MAX_DISPLAY} elements")
        c.display = []
        for j, e in enumerate(arr):
            da = f"{at}.display[{j}]"
            if not isinstance(e, dict):
                raise _claims_err(f"{da} is not an object")
            loc = e.get("locale")
            if not isinstance(loc, str) or not well_formed_lang_tag(loc):
                raise _claims_err(f"{da}.locale is absent or not a well-formed language tag")
            lab = e.get("label")
            if not isinstance(lab, str):
                raise _claims_err(f"{da}.label is absent or not a string")
            desc = e.get("description", "")
            if "description" in e and not isinstance(desc, str):
                raise _claims_err(f"{da}.description is not a string")
            c.display.append(ClaimDisplay(locale=loc, label=lab, description=desc or ""))
    if "mandatory" in v:
        meta.has_mandatory = True
        if not isinstance(v["mandatory"], bool):
            raise _claims_err(f"{at}.mandatory is not a boolean")
        c.mandatory = v["mandatory"]
    if "sd" in v:
        meta.has_sd = True
        sd = v["sd"]
        if sd not in (SD_ALWAYS, SD_ALLOWED, SD_NEVER):
            raise _claims_err(f"{at}.sd is not always, allowed or never")
        c.sd = sd
    if "svg_id" in v:
        meta.has_svg_id = True
        sid = v["svg_id"]
        if not isinstance(sid, str) or not _svg_id(sid):
            raise _claims_err(f"{at}.svg_id is not alphanumerics and underscores starting with no digit")
        c.svg_id = sid
    return meta


def _svg_id(s: str) -> bool:
    if not s or "0" <= s[0] <= "9":
        return False
    allowed = set("_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    return all(c in allowed for c in s)


def _check_svg_ids(claims: list[_ClaimMeta]) -> Exception | None:
    seen: set[str] = set()
    for i, c in enumerate(claims):
        sid = c.claim.svg_id
        if not sid:
            continue
        if sid in seen:
            return _claims_err(f"claims[{i}].svg_id is used by another claim")
        seen.add(sid)
    return None


def merge_claims_impl(inherited: list[_ClaimMeta], child: list[_ClaimMeta]) -> list[_ClaimMeta]:
    out = list(inherited)
    by_path: dict[str, list[int]] = {}
    for j, p in enumerate(inherited):
        by_path.setdefault(path_key(p.claim.path), []).append(j)
    for i, c in enumerate(child):
        matches = by_path.get(path_key(c.claim.path), [])
        for j in matches:
            p = out[j]
            if c.has_sd:
                if p.has_sd and p.claim.sd != SD_ALLOWED and c.claim.sd != p.claim.sd:
                    raise _claims_err(f"claims[{i}] changes an inherited sd of {p.claim.sd}")
                p.claim.sd = c.claim.sd
                p.has_sd = True
            if c.has_mandatory:
                if p.claim.mandatory and not c.claim.mandatory:
                    raise _claims_err(f"claims[{i}] changes an inherited mandatory true to false")
                p.claim.mandatory = c.claim.mandatory
                p.has_mandatory = True
            if c.has_display:
                p.claim.display = list(c.claim.display)
                p.has_display = True
            if c.has_svg_id:
                p.claim.svg_id = c.claim.svg_id
                p.has_svg_id = True
        if not matches:
            out.append(c)
    return out


def path_key(path: list[Any]) -> str:
    parts: list[str] = []
    for el in path:
        if isinstance(el, str):
            parts.append(f"s{len(el)}:{el}")
        elif el is None:
            parts.append("n")
        else:
            parts.append(f"i{int(el)};")
    return "".join(parts)


def _invalid(msg: str) -> ErrInvalid:
    return ErrInvalid(f"typemeta: {msg}")


def _claims_err(msg: str) -> ErrClaims:
    return ErrClaims(f"typemeta: {msg}")
