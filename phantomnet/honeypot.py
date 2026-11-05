"""Asyncio TCP honeypot with a fake login + shell (telnet/netcat style)."""
import asyncio
import re
import time

from .session import Session

BANNER = "Ubuntu 22.04.3 LTS\r\n"
MOTD = ("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n\r\n"
        "Last login: Mon Oct 12 08:57:31 2026 from 10.0.2.2\r\n")
IAC = re.compile(rb"\xff[\xfb-\xfe].|\xff\xff")


async def read_line(reader, timeout):
    try:
        data = await asyncio.wait_for(reader.readline(), timeout)
    except asyncio.TimeoutError:
        return None
    if not data:
        return None
    data = IAC.sub(b"", data)
    return data.decode("utf-8", "replace").strip("\r\n")


def _write(writer, text):
    writer.write(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())


async def handle_client(reader, writer, cfg, engine, log):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    s = Session(ip=str(peer[0]), port=peer[1], hostname=cfg.hostname)
    log.event(s, "connect", port=peer[1])
    try:
        _write(writer, BANNER)
        authed = False
        for attempt in range(3):
            _write(writer, f"{cfg.hostname} login: ")
            await writer.drain()
            user = await read_line(reader, 60)
            if user is None:
                return
            _write(writer, "Password: ")
            await writer.drain()
            pw = await read_line(reader, 60)
            if pw is None:
                return
            log.event(s, "login_attempt", username=user, password=pw, attempt=attempt)
            if attempt >= cfg.accept_after and user:
                s.user = user if re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) else "root"
                s.cwd = s.home
                authed = True
                break
            _write(writer, "\r\nLogin incorrect\r\n")
        if not authed:
            return
        log.event(s, "login_success", username=s.user)
        _write(writer, MOTD)
        while time.time() - s.started < cfg.max_session_seconds:
            _write(writer, s.prompt())
            await writer.drain()
            line = await read_line(reader, cfg.idle_timeout)
            if line is None:
                break
            if not line.strip():
                continue
            out, done = await engine.handle(s, line)
            if out:
                _write(writer, out + "\r\n")
            if done:
                break
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        log.event(s, "disconnect", duration=round(time.time() - s.started, 2), commands=len(s.history))
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def serve(cfg, engine, log):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, cfg, engine, log), cfg.host, cfg.port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[PhantomNet] honeypot listening on {addrs} (backend={engine.backend.name})", flush=True)
    async with server:
        await server.serve_forever()
