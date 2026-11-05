"""Structured event logging: JSON Lines + SQLite (for the dashboard)."""
import json
import os
import sqlite3
import time


class EventLogger:
    def __init__(self, log_dir="logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.jsonl_path = os.path.join(log_dir, "events.jsonl")
        self.db_path = os.path.join(log_dir, "events.db")
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ts REAL, session TEXT, ip TEXT, type TEXT, data TEXT)"
        )
        self.db.commit()

    def event(self, session, etype, **data):
        rec = {"ts": time.time(), "session": session.id, "ip": session.ip, "type": etype, **data}
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        self.db.execute(
            "INSERT INTO events (ts, session, ip, type, data) VALUES (?,?,?,?,?)",
            (rec["ts"], rec["session"], rec["ip"], etype, json.dumps(data)),
        )
        self.db.commit()
        return rec
