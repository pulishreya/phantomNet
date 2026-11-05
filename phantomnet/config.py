import os
from dataclasses import dataclass, field


def _env(name, default):
    return os.getenv(name, default)


@dataclass
class Config:
    host: str = field(default_factory=lambda: _env("PN_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: int(_env("PN_PORT", "2222")))
    backend: str = field(default_factory=lambda: _env("PN_BACKEND", "mock"))  # mock | anthropic | ollama
    model: str = field(default_factory=lambda: _env("PN_MODEL", "claude-sonnet-5-5"))
    ollama_url: str = field(default_factory=lambda: _env("PN_OLLAMA_URL", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: _env("PN_OLLAMA_MODEL", "llama3"))
    log_dir: str = field(default_factory=lambda: _env("PN_LOG_DIR", "logs"))
    hostname: str = field(default_factory=lambda: _env("PN_HOSTNAME", "srv-db-01"))
    accept_after: int = 1            # accept login on this attempt index (0 = first try)
    max_session_seconds: int = 600   # hard cap per attacker session
    idle_timeout: int = 120
