import argparse
import asyncio
import json
import os

from .config import Config
from .dashboard import compute_stats, run_dashboard
from .engine import Engine
from .honeypot import serve
from .llm import get_backend
from .logger import EventLogger


def main():
    ap = argparse.ArgumentParser(prog="phantomnet", description="PhantomNet - LLM honeypot")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="start the honeypot")
    r.add_argument("--port", type=int)
    r.add_argument("--backend", choices=["mock", "anthropic", "ollama"])
    d = sub.add_parser("dashboard", help="start the web dashboard")
    d.add_argument("--port", type=int, default=8080)
    sub.add_parser("report", help="print a JSON summary of captured activity")
    a = ap.parse_args()

    cfg = Config()
    if a.cmd == "run":
        if a.port:
            cfg.port = a.port
        if a.backend:
            cfg.backend = a.backend
        log = EventLogger(cfg.log_dir)
        asyncio.run(serve(cfg, Engine(cfg, get_backend(cfg), log), log))
    elif a.cmd == "dashboard":
        EventLogger(cfg.log_dir)  # ensures DB exists
        run_dashboard(os.path.join(cfg.log_dir, "events.db"), a.port)
    else:
        EventLogger(cfg.log_dir)
        print(json.dumps(compute_stats(os.path.join(cfg.log_dir, "events.db")), indent=2))


if __name__ == "__main__":
    main()
