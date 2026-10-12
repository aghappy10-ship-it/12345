"""One-shot private Release transfer; no source changes or camera operations."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import time

GH = Path(r"F:\Codex\2026-08-19\x2d2-asset-transfer\gh-2.102.0\bin\gh.exe")
ARCHIVES = Path(r"F:\Codex\2026-08-19\x2d2-asset-transfer\archives")
REPO = "aghappy10-ship-it/12345"
RELEASE_ID = 410451741
TAG = "research-assets-20261012"
LABELS = (
    "factual-handoff-document", "reference-windows-installer",
    "reference-extension-toolkit", "historical-handoff-complete",
    "frozen-x2d2-complete", "independent-worktree-complete",
    "active-reference-complete", "user-reference-screenshot",
)
ENV = {**os.environ, "HTTPS_PROXY": "http://127.0.0.1:7890"}
RESULT = ARCHIVES / "ASSET_UPLOAD_RESULT.json"


def gh(*args):
    result = subprocess.run([str(GH), *args], env=ENV, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-2000:])
    return result.stdout.decode("utf-8")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def private_release():
    repository = json.loads(gh("api", "repos/" + REPO))
    if repository.get("full_name") != REPO or repository.get("private") is not True:
        raise RuntimeError("Refuse asset transmission: target is not the selected private repository")
    release = json.loads(gh("api", f"repos/{REPO}/releases/{RELEASE_ID}"))
    if release.get("tag_name") != TAG or release.get("draft") is not True:
        raise RuntimeError("Expected owned draft Release differs")
    return release


def publish_record(record):
    # Generated progress record, not a firmware qualification or source edit.
    temporary = RESULT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(RESULT)


def read_state(path):
    # The existing archive writer saves in place. Retry only a bounded read
    # collision/partial JSON; a valid FAILED state must reach main immediately.
    for attempt in range(10):
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            if attempt == 9:
                raise
            time.sleep(0.2)


def local_files(label, state):
    if state.get("state") != "VERIFIED_LOCAL_NOT_UPLOADED":
        raise RuntimeError("Unverified archive state")
    before, after = state["source_before"], state["source_after"]
    if before["sha256"] != after["sha256"]:
        raise RuntimeError("Source changed during archive")
    if state.get("archive_exit_code") != 0 or state.get("archive_test_exit_code") != 0:
        raise RuntimeError("Archive generation/integrity was not successful")
    if label == "historical-handoff-complete" and set(state.get("excluded_relative_paths", [])) != {
        "Job_0000.3fr", "Job_0000.3fr.phos"
    }:
        raise RuntimeError("Photo exclusion differs from user choice")
    if label == "active-reference-complete" and "devtools/data/connection.json" not in {
        value.replace("\\", "/") for value in state.get("excluded_relative_paths", [])
    }:
        raise RuntimeError("Active connection credential exclusion is missing")
    # Archive test counts, not 'files read from disk': empty files need no read.
    test_log = (ARCHIVES / f"{label}.archive-test.log").read_text(encoding="utf-8-sig")
    sizes = re.findall(r"^Size:\s*(\d+)\s*$", test_log, re.MULTILINE)
    counts = re.findall(r"^Files:\s*(\d+)\s*$", test_log, re.MULTILINE)
    file_links = [row for row in before.get("reparse_entries", []) if row.get("kind") == "file"]
    expected_count = before["files"] - len(file_links)
    expected_size = before["bytes"] - sum(row["bytes"] for row in file_links)
    if not sizes or int(sizes[-1]) != expected_size:
        raise RuntimeError("Archive's tested byte total differs from source inventory")
    actual_count = int(counts[-1]) if counts else 1
    if actual_count != expected_count:
        raise RuntimeError("Archive's tested file count differs from source inventory")
    volume_names = [volume["name"] for volume in state["volumes"]]
    disk_names = sorted(path.name for path in ARCHIVES.glob(f"{label}.7z.*"))
    test_volumes = re.findall(r"^Volumes = (\d+)\s*$", test_log, re.MULTILINE)
    if not volume_names or disk_names != volume_names or len(test_volumes) != 1 or \
            int(test_volumes[0]) != len(volume_names):
        raise RuntimeError("Archive volume sets/count differ between state, disk and integrity test")
    files = []
    for number, volume in enumerate(state["volumes"], 1):
        if volume["name"] != f"{label}.7z.{number:03d}":
            raise RuntimeError("Invalid volume name or sequence")
        path = ARCHIVES / volume["name"]
        if path.stat().st_size != volume["bytes"] or digest(path) != volume["sha256"]:
            raise RuntimeError("Archive volume differs from verified bytes")
        files.append((path, volume["sha256"]))
    if not files:
        raise RuntimeError("No archive volumes")
    for suffix, inventory in (("source-before.ndjson", before), ("source-after.ndjson", after)):
        path = ARCHIVES / f"{label}.{suffix}"
        sha = digest(path)
        if sha != inventory["sha256"]:
            raise RuntimeError("Source inventory differs from its verified SHA256 binding")
        files.append((path, sha))
    state_path = ARCHIVES / f"{label}.state.json"
    if read_state(state_path) != state:
        raise RuntimeError("Verified archive state changed before transfer")
    files.append((state_path, digest(state_path)))
    return files


def main():
    if RESULT.exists():
        raise FileExistsError("Do not restart an existing upload worker without reading its result")
    record = {"repository": REPO, "release_id": RELEASE_ID, "tag": TAG,
              "state": "WAITING_FOR_ARCHIVES", "complete": False, "installable": False,
              "roots": {}, "started_unix": time.time(), "camera_accesses": 0}
    publish_record(record)
    try:
        while len(record["roots"]) < len(LABELS):
            progressed = False
            for label in LABELS:
                if label in record["roots"]:
                    continue
                path = ARCHIVES / f"{label}.state.json"
                if not path.exists():
                    continue
                state = read_state(path)
                if state.get("state") == "FAILED_LOCAL_NOT_UPLOADED":
                    raise RuntimeError(f"Archive failed: {label}: {state.get('error')}")
                if state.get("state") != "VERIFIED_LOCAL_NOT_UPLOADED":
                    continue
                files = local_files(label, state)
                release = private_release()
                rows = []
                for asset, sha in files:
                    record.update(state="UPLOADING", current_file=asset.name)
                    publish_record(record)
                    matches = [item for item in release["assets"] if item["name"] == asset.name]
                    if len(matches) > 1:
                        raise RuntimeError("Duplicate remote asset names")
                    if not matches:
                        gh("release", "upload", TAG, str(asset), "--repo", REPO)
                        release = private_release()
                        matches = [item for item in release["assets"] if item["name"] == asset.name]
                    if len(matches) != 1:
                        raise RuntimeError("Remote asset is missing after upload")
                    item = matches[0]
                    if item.get("state") != "uploaded" or item.get("size") != asset.stat().st_size or \
                            item.get("digest") != "sha256:" + sha:
                        raise RuntimeError("Remote asset length or SHA256 differs; do not overwrite")
                    rows.append({"name": asset.name, "bytes": item["size"], "sha256": sha,
                                 "id": item["id"], "url": item["browser_download_url"]})
                record["roots"][label] = {"source": state["source"], "files": state["source_before"]["files"],
                    "bytes": state["source_before"]["bytes"], "links": before_links_count(state),
                    "excluded": state.get("excluded_relative_paths", []), "assets": rows}
                record.update(state="WAITING_FOR_ARCHIVES", current_file=None)
                publish_record(record)
                print(json.dumps({"root_uploaded_verified": label, "assets": len(rows)}), flush=True)
                progressed = True
            if not progressed:
                time.sleep(10)
        record.update(state="ALL_ASSETS_UPLOADED_DRAFT_AWAITING_FINAL_INDEX",
                      complete=False, finished_unix=time.time())
        publish_record(record)
    except BaseException as error:
        record.update(state="FAILED_NOT_COMPLETE", error=str(error), complete=False)
        publish_record(record)
        raise


def before_links_count(state):
    return len(state["source_before"].get("reparse_entries", []))


if __name__ == "__main__":
    main()
