import argparse
import json
import sys
import time
from pathlib import Path

from .format import decode, fingerprint


def main():
    parser = argparse.ArgumentParser(description="Independent, optional browser / AyuGram recorder")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start an independent panel; capture starts disabled")
    serve.add_argument("--data", type=Path, required=True)
    serve.add_argument("--config", type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8791)
    identity = commands.add_parser("identity", help="Read the public recorder identity without opening its journal")
    identity.add_argument("--data", type=Path, required=True)
    verify = commands.add_parser("verify", help="Verify an export without any running recorder or TgWitness")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--fingerprint")
    verify.add_argument("--checkpoint", type=Path)
    verify.add_argument("--receipt", type=Path)
    verify.add_argument("--witness-fingerprint")
    verify.add_argument("--require-final-anchor", action="store_true")
    witness = commands.add_parser("witness", help="Retain fresh signed checkpoints on an independent host")
    witness.add_argument("--data", type=Path, required=True)
    witness.add_argument("--url", required=True)
    witness.add_argument("--token-file", type=Path, required=True)
    witness.add_argument("--fingerprint", required=True)
    witness.add_argument("--interval", type=float, default=60)
    witness.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.command == "serve":
        if not 1 <= args.port <= 65535:
            parser.error("Invalid port")
        import uvicorn
        from .service import Config, create_app
        config = Config.load(args.config)
        print("Capture starts disabled. Log in to the source manually before enabling capture.")
        print("Control token:", args.data.resolve() / "control-token.txt")
        print("Read-only witness token:", args.data.resolve() / "witness-token.txt")
        uvicorn.run(create_app(args.data, config), host=args.host, port=args.port,
                    access_log=False, workers=1, proxy_headers=False)
    elif args.command == "identity":
        saved = decode((args.data / "identity.json").read_bytes())
        print(json.dumps({"observer_id": saved["observer_id"], "public_key": saved["public_key"],
                          "fingerprint": fingerprint(saved["public_key"])}, indent=2))
    elif args.command == "verify":
        from .verify import verify_zip
        try:
            result = verify_zip(args.archive, args.fingerprint,
                                decode(args.checkpoint.read_bytes()) if args.checkpoint else None,
                                decode(args.receipt.read_bytes()) if args.receipt else None,
                                args.witness_fingerprint, args.require_final_anchor)
        except Exception as exc:
            print(json.dumps({"valid": False, "error": str(exc) or type(exc).__name__}))
            raise SystemExit(1) from None
        print(json.dumps(result, indent=2))
    else:
        if not 1 <= args.interval <= 86400:
            parser.error("Witness interval must be between 1 and 86400 seconds")
        from .journal import Journal
        from .witness import witness_once
        journal = Journal(args.data)
        journal.append("service.started", {"kind": "witness"})
        print("Witness key SHA-256:", journal.fingerprint, flush=True)
        try:
            while True:
                try:
                    receipt = witness_once(journal, args.url, args.token_file.read_text().strip(), args.fingerprint)
                    print("Receipt:", receipt, flush=True)
                except Exception as exc:
                    journal.append("witness.failed", {"error": type(exc).__name__})
                    print("Checkpoint unavailable or rejected:", type(exc).__name__, file=sys.stderr, flush=True)
                    if args.once:
                        raise SystemExit(1) from None
                if args.once:
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass
        finally:
            journal.append("service.stopped", {})
            journal.close()


if __name__ == "__main__":
    main()
