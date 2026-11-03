from credential.vp.json_presentation import JSONPresentation


def test_json_presentation_create_sets_defaults():
    vp = JSONPresentation.create({"holder": "did:example:holder"})
    assert "VerifiablePresentation" in vp.data["type"]
