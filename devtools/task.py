"""Cooperative task client. Registers work; does not start or control AI agents."""
import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description="向当前本地工作台登记任务进展")
    parser.add_argument("task_id", help="工作台任务ID，例如entry")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--state", choices=["todo", "doing", "blocked", "done"], required=True)
    parser.add_argument("--note", default="")
    args = parser.parse_args()
    info = json.loads((Path(__file__).resolve().parent / "data/connection.json").read_text(encoding="utf-8"))
    with urlopen(info["url"] + "/api/state", timeout=5) as response:
        state = json.load(response)
    request = Request(info["url"] + "/api/tasks/" + args.task_id,
                      data=json.dumps({"revision": state["board"]["revision"], "owner": args.owner,
                                       "state": args.state, "note": args.note, "heartbeat": True}).encode(),
                      headers={"Content-Type": "application/json", "X-Session-Token": info["token"]}, method="POST")
    with urlopen(request, timeout=5) as response:
        print(json.load(response)["revision"])


if __name__ == "__main__":
    main()
