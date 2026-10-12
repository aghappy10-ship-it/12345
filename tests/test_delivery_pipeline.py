"""Real host assembly/persistence cores, inert data and TEST_ONLY commit.

This does not exercise a successful qualified prepare() call or manufacture
camera evidence. No current payload bytes or executable installer are used.
"""
import io
import json
import tarfile

from tests.test_delivery_files import synthetic_tree, candidate_hash
from tools.delivery_files import assemble_delivery
from tools.delivery_content import verify_content
from tools.output_guard import publish_output_set


def test_same_rendered_synthetic_bytes_survive_assembly_and_committed_host_readback(synthetic_tree):
    root, members, candidate, scripts = synthetic_tree
    assembly = assemble_delivery(candidate, candidate_hash(candidate), scripts, source_root=root)
    output = root / "INERT-TEST-ONLY-DELIVERY"
    outputs = {name: value.encode("ascii") for name, value in scripts.items()}
    outputs["session-context.data"] = b"TEST_ONLY NO SESSION AUTHORITY\n"
    outputs["x2dii-menu-content.tar"] = assembly["archive_bytes"]
    marker = {"status": "TEST_ONLY", "installable": False,
              "delivery_identity": assembly["delivery_identity"]}
    outputs["peer-install-source.json"] = json.dumps(marker).encode("ascii")
    calls = []

    def precommit():
        assert not (output / "peer-install-source.json").exists()
        for name, raw in outputs.items():
            if name != "peer-install-source.json":
                assert (output / name).read_bytes() == raw
        calls.append("observed all inert members before marker")

    assert publish_output_set(output, outputs, commit_name="peer-install-source.json",
                              before_commit=precommit) == output
    assert len(calls) == 1
    raw = (output / "x2dii-menu-content.tar").read_bytes()
    assert verify_content(raw, assembly["content_manifest"]) == assembly["delivery_identity"]
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        assert archive.getnames() == [*members, "members.json"]
        for name, expected in members.items():
            assert archive.extractfile(name).read() == expected
            if name in scripts:
                assert (output / name).read_bytes() == expected
    assert json.loads((output / "peer-install-source.json").read_bytes()) == marker

