from __future__ import annotations

import argparse
from wsgiref.simple_server import make_server

from .app import application


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the digital resource provenance HTTP service."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    with make_server(args.host, args.port, application) as server:
        print(f"provenance-api listening on http://{args.host}:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("provenance-api stopped", flush=True)


if __name__ == "__main__":
    main()

