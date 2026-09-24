from __future__ import annotations

import argparse
import re
from wsgiref.simple_server import make_server

from .app import application, configure_cache_quota
from .cache import DEFAULT_CACHE_QUOTA

#: ``--cache-quota`` must be a decimal positive integer (no sign, no
#: leading zeros, no whitespace).
_POSITIVE_INT_PATTERN = re.compile(r"[1-9][0-9]*")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the digital resource provenance HTTP service."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--cache-quota",
        default=str(DEFAULT_CACHE_QUOTA),
        metavar="BYTES",
        help=(
            "total byte quota for the image layer cache "
            f"(decimal positive integer, default {DEFAULT_CACHE_QUOTA})"
        ),
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if _POSITIVE_INT_PATTERN.fullmatch(args.cache_quota) is None:
        # Refuse to start: print usage and exit non-zero.
        parser.error("--cache-quota must be a decimal positive integer")
    configure_cache_quota(int(args.cache_quota))
    with make_server(args.host, args.port, application) as server:
        print(f"provenance-api listening on http://{args.host}:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("provenance-api stopped", flush=True)


if __name__ == "__main__":
    main()
