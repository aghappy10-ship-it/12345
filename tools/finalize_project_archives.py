"""Publish this one private research archive after all eight roots are verified."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import subprocess
from urllib.parse import quote

import upload_project_archives as transfer

ROOT = Path(__file__).resolve().parent.parent
FINAL_RESULT = transfer.ARCHIVES / "FINAL_ASSET_PUBLICATION.json"
MISSING = [
    "codex-clipboard-c94219be-718a-4e2d-83a2-05cd34bfa551.jpg",
    "codex-clipboard-627868ea-be65-41cc-a830-def525175e96.jpg",
]


def git(*arguments):
    result = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-2000:])
    return result.stdout.decode("utf-8").strip()


def verify_assets(release, expected, *, exact=False):
    if exact:
        names = [row["name"] for row in expected]
        actual = [row["name"] for row in release["assets"]]
        if len(set(names)) != len(names) or len(set(actual)) != len(actual) or sorted(names) != sorted(actual):
            raise RuntimeError("Complete Release attachment set differs from the final index")
    for row in expected:
        matches = [item for item in release["assets"] if item["name"] == row["name"]]
        if len(matches) != 1:
            raise RuntimeError(f"Missing/duplicate remote asset: {row['name']}")
        item = matches[0]
        if item.get("state") != "uploaded" or item.get("size") != row["bytes"] or \
                item.get("digest") != "sha256:" + row["sha256"]:
            raise RuntimeError(f"Remote content mismatch: {row['name']}")


def make_index(record, release):
    if record.get("state") != "ALL_ASSETS_UPLOADED_DRAFT_AWAITING_FINAL_INDEX" or \
            set(record.get("roots", {})) != set(transfer.LABELS) or \
            record.get("repository") != transfer.REPO or record.get("release_id") != transfer.RELEASE_ID:
        raise RuntimeError("Full transfer is not closed for the selected repository/Release")
    rows = []
    for label in transfer.LABELS:
        root = record["roots"][label]
        state = transfer.read_state(transfer.ARCHIVES / f"{label}.state.json")
        if state.get("state") != "VERIFIED_LOCAL_NOT_UPLOADED" or \
                state["source_before"]["sha256"] != state["source_after"]["sha256"] or \
                root["source"] != state["source"] or root["files"] != state["source_before"]["files"] or \
                root["bytes"] != state["source_before"]["bytes"] or \
                root["excluded"] != state.get("excluded_relative_paths", []):
            raise RuntimeError(f"Root/state binding differs: {label}")
        expected = {v["name"]: (v["bytes"], v["sha256"]) for v in state["volumes"]}
        for suffix in ("state.json", "source-before.ndjson", "source-after.ndjson"):
            path = transfer.ARCHIVES / f"{label}.{suffix}"
            expected[path.name] = (path.stat().st_size, transfer.digest(path))
        recorded = {v["name"]: (v["bytes"], v["sha256"]) for v in root["assets"]}
        if len(recorded) != len(root["assets"]) or recorded != expected:
            raise RuntimeError(f"Root attachments differ from verified local state: {label}")
        verify_assets(release, root["assets"])
        assets = [{**v, "url": f"https://github.com/{transfer.REPO}/releases/download/"
                   f"{transfer.TAG}/{quote(v['name'])}"} for v in root["assets"]]
        rows.append({**root, "label": label, "assets": assets,
                     "inventory_sha256": state["source_before"]["sha256"],
                     "volume_count": len(state["volumes"]),
                     "link_description": f"{label}.state.json and source inventories"})
    verify_assets(release, [row for root in rows for row in root["assets"]], exact=True)
    return {"schema": "x2dii-full-project-assets-index-v1", "repository": transfer.REPO,
            "tag": transfer.TAG, "release_id": transfer.RELEASE_ID,
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
            "all_existing_roots_uploaded_verified": True, "installable": False,
            "release_was_draft_at_verification": release["draft"],
            "source_publication_commit": git("rev-parse", "HEAD"),
            "roots": rows, "missing_historical_attachments": MISSING,
            "excluded_user_photo": [r"D:\x2d\Job_0000.3fr", r"D:\x2d\Job_0000.3fr.phos"],
            "excluded_runtime_credential": "devtools/data/connection.json",
            "limits": "Archive CRC and stable source inventories; not independent per-source-file SHA256, ACL/ADS or NTFS forensic image"}


def render_index(index):
    lines = ["# 完整工程资产下载索引", "",
             "八组现存工程资产已逐附件核对GitHub长度和SHA256。此索引建立时Release仍为草稿；发布后的下载入口如下。", "",
             f"[私有资产Release](https://github.com/{transfer.REPO}/releases/tag/{transfer.TAG})", "",
             "**这是研究资产，不是可安装固件。** 旧失败候选、测试夹具与第三方安装器不因归档获得安装资格。", "",
             "| 资产组 | 原件文件数 | 原件字节数 | 压缩卷数 | 压缩字节数 |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for root in index["roots"]:
        size = sum(row["bytes"] for row in root["assets"] if ".7z." in row["name"])
        lines.append(f"| {root['label']} | {root['files']:,} | {root['bytes']:,} | {root['volume_count']} | {size:,} |")
    lines += ["", "## 下载和恢复", "",
              "每组下载所有 `.7z.001`、`.002` 等卷到同一目录，从 `.001` 开始用7-Zip解压。卷SHA256及下载链接见同目录的 `FULL_ASSET_INDEX.json`。目录清单与state附件也需保留。", "",
              "只解压到新的恢复位置，不覆盖原工程；先检查历史路径和链接目标，再恢复链接。冻结独立工作树的Git指针依赖冻结主工程，二者需共同恢复。", "",
              "目录/文件链接在清单中保留描述，普通7z载荷不跟随这些链接。不是完整NTFS/ACL/ADS镜像。C盘Codex目录是F盘别名，不重复保存。", "",
              "## 排除和缺失", "",
              "按用户要求排除真实照片 `Job_0000.3fr` 及配套 `.phos`；活动工作台的 `connection.json` 会话令牌不上传。上游测试材料、重复镜像和临时pack没有因可重生成而删减。", "",
              "两张已丢失的早期临时截图没有上传：", ""]
    lines += [f"- `{name}`" for name in MISSING]
    lines += ["", "现存第三张用户参考截图单独保留，不作为本项目实测性能证明。", ""]
    return "\n".join(lines)


def checkpoint(result, stage):
    result["state"] = stage
    temporary = FINAL_RESULT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(FINAL_RESULT)


def wait_for_upload():
    last_count = None
    while True:
        record = transfer.read_state(transfer.RESULT)
        count = len(record.get("roots", {}))
        if count != last_count:
            print(json.dumps({"verified_roots": count, "required_roots": len(transfer.LABELS)}), flush=True)
            last_count = count
        if record.get("state") == "ALL_ASSETS_UPLOADED_DRAFT_AWAITING_FINAL_INDEX":
            return
        if record.get("state") not in {"WAITING_FOR_ARCHIVES", "UPLOADING"}:
            raise RuntimeError("Upload did not complete; keep the Release draft")
        transfer.time.sleep(10)


def main():
    if FINAL_RESULT.exists():
        raise FileExistsError("Read the existing finalization record before any restart")
    result = {"complete": False, "installable": False, "repository": transfer.REPO}
    try:
        checkpoint(result, "VERIFYING_ALL_ROOTS")
        release = transfer.private_release()
        index = make_index(transfer.read_state(transfer.RESULT), release)
        paths = [ROOT / "docs/FULL_ASSET_INDEX.json", ROOT / "docs/FULL_ASSET_INDEX.md"]
        if any(path.exists() for path in paths) or git("status", "--porcelain"):
            raise RuntimeError("Publication tree must be clean and index outputs absent")
        checkpoint(result, "WRITING_FINAL_INDEX")
        paths[0].write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        paths[1].write_text(render_index(index), encoding="utf-8")
        readme = ROOT / "README.md"
        text = readme.read_text(encoding="utf-8")
        old = [line for line in text.splitlines() if line.startswith("**2026-10-12 全量资产补充正在进行：**")]
        if len(old) != 1:
            raise RuntimeError("Expected publication status paragraph differs")
        text = text.replace(old[0], "**2026-10-12 现存工程资产已上传核对：**首个263文件提交是阅读快照；"
                            "完整的8组工程资产另以私有Release分卷保存，包括原厂研究材料、镜像、日志、依赖和失败原件。"
                            "[完整下载索引](docs/FULL_ASSET_INDEX.md)列出文件数、体积、分卷及恢复办法。"
                            "真实照片与运行会话令牌已排除；两张已经丢失的早期临时截图没有上传，索引如实注明。")
        readme.write_text(text, encoding="utf-8")
        paths_to_commit = paths + [readme]
        checkpoint(result, "COMMITTING_FINAL_INDEX")
        git("add", "--", *(str(path.relative_to(ROOT)) for path in paths_to_commit))
        git("diff", "--cached", "--check")
        git("commit", "-m", "docs: index all verified private project asset archives")
        checkpoint(result, "PUSHING_FINAL_INDEX")
        git("-c", "http.proxy=http://127.0.0.1:7890", "push", "origin", "HEAD:main")
        commit = git("rev-parse", "HEAD")
        remote = json.loads(transfer.gh("api", f"repos/{transfer.REPO}/git/ref/heads/main"))
        if remote["object"]["sha"] != commit:
            raise RuntimeError("Final index commit is not the remote main commit")
        tag = f"refs/tags/{transfer.TAG}"
        existing = git("-c", "http.proxy=http://127.0.0.1:7890", "ls-remote", "origin", tag, tag + "^{}")
        tag_rows = dict(line.split("\t")[::-1] for line in existing.splitlines())
        if tag_rows and tag_rows.get(tag + "^{}", tag_rows.get(tag)) != commit:
            raise RuntimeError("Existing asset tag points elsewhere; do not replace it")
        index_rows = []
        for path in paths:
            checkpoint(result, "UPLOADING_" + path.name)
            transfer.gh("release", "upload", transfer.TAG, str(path), "--repo", transfer.REPO)
            index_rows.append({"name": path.name, "bytes": path.stat().st_size,
                               "sha256": transfer.digest(path)})
        release = transfer.private_release()
        expected = [row for root in index["roots"] for row in root["assets"]] + index_rows
        verify_assets(release, expected, exact=True)
        checkpoint(result, "PUBLISHING_VERIFIED_PRIVATE_RELEASE")
        transfer.gh("api", "-X", "PATCH", f"repos/{transfer.REPO}/releases/{transfer.RELEASE_ID}",
                    "-f", "target_commitish=" + commit, "-F", "draft=false")
        checkpoint(result, "VERIFYING_PUBLISHED_PRIVATE_RELEASE")
        repository = json.loads(transfer.gh("api", "repos/" + transfer.REPO))
        release = json.loads(transfer.gh("api", f"repos/{transfer.REPO}/releases/{transfer.RELEASE_ID}"))
        if repository.get("private") is not True or release.get("draft") is not False or \
                release.get("tag_name") != transfer.TAG:
            raise RuntimeError("Private published Release identity differs")
        verify_assets(release, expected, exact=True)
        tag_ref = json.loads(transfer.gh("api", f"repos/{transfer.REPO}/git/ref/tags/{transfer.TAG}"))["object"]
        if tag_ref["type"] == "tag":
            tag_ref = json.loads(transfer.gh("api", f"repos/{transfer.REPO}/git/tags/{tag_ref['sha']}"))["object"]
        if tag_ref.get("type") != "commit" or tag_ref.get("sha") != commit:
            raise RuntimeError("Published asset tag is not bound to the final index commit")
        result.update(complete=True, state="ALL_EXISTING_PROJECT_ASSETS_PUBLISHED_VERIFIED",
                      commit=commit, release_url=release["html_url"], roots=len(index["roots"]),
                      verified_attachments=len(expected), missing_historical_attachments=MISSING)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    except BaseException as error:
        result.update(state="FINALIZATION_FAILED_NOT_COMPLETE", error=str(error))
        raise
    finally:
        checkpoint(result, result["state"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-for-upload", action="store_true")
    if parser.parse_args().wait_for_upload:
        wait_for_upload()
    main()
