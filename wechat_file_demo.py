import argparse
import json
from pathlib import Path

import msg_push


def build_parser():
    # Build command line arguments for the WeCom file message demo.
    parser = argparse.ArgumentParser(
        description="Upload a local file to a WeCom webhook robot and send it as a file message."
    )
    parser.add_argument("file", help="Local file path to send.")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print single-line JSON output.",
    )
    return parser


def main():
    # Run the file upload + send flow and print the result JSON.
    parser = build_parser()
    args = parser.parse_args()
    file_path = Path(args.file).expanduser().resolve()
    result = {
        "file": str(file_path),
    }
    try:
        payload = msg_push.wechat_push_file(str(file_path))
        result["ok"] = True
        result["upload"] = payload["upload"]
        result["send"] = payload["send"]
    except Exception as exc:
        result["ok"] = False
        result["error"] = str(exc)

    if args.compact:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
