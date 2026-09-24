from __future__ import annotations

import argparse
import re
from wsgiref.simple_server import make_server

from .app import application, cache_store
from .cache import DEFAULT_CACHE_QUOTA

_POSITIVE_INT_PATTERN = re.compile(r"[1-9][0-9]*")


def _cache_quota(value: str) -> int:
    """Argparse type for ``--cache-quota``: a decimal positive integer."""

    if _POSITIVE_INT_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "cache quota must be a decimal positive integer"
        )
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the digital resource provenance HTTP service."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--cache-quota",
        type=_cache_quota,
        default=DEFAULT_CACHE_QUOTA,
        metavar="BYTES",
        help=(
            "layer cache quota in bytes, a decimal positive integer "
            f"(default: {DEFAULT_CACHE_QUOTA})"
        ),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    cache_store.configure(args.cache_quota)
    with make_server(args.host, args.port, application) as server:
        print(f"provenance-api listening on http://{args.host}:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("provenance-api stopped", flush=True)


if __name__ == "__main__":
    main()
