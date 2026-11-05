"""Command engine: deterministic core (stateful) + generative long tail (LLM)."""
import posixpath
import re
import shlex

from .mitre import tag
from .session import HONEYTOKENS

INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above)|system prompt|language model|as an ai\b|"
    r"you are (an? )?(ai|llm|chatbot|assistant)|reveal your (prompt|instructions)", re.I)

UNAME_A = "Linux {h} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"


class Engine:
    def __init__(self, cfg, backend, logger):
        self.cfg, self.backend, self.log = cfg, backend, logger

    async def handle(self, s, line):
        """Returns (output, should_exit). Logs every command with ATT&CK tags."""
        line = line.strip()
        techniques = tag(line)
        self.log.event(s, "command", command=line, techniques=techniques)
        if INJECTION.search(line):
            self.log.event(s, "prompt_injection_attempt", command=line)
            first = line.split()[0] if line.split() else line
            out = f"bash: {first}: command not found"
            s.history.append([line, out])
            return out, False

        segments = [line] if re.search(r"""["']""", line) else [x for x in re.split(r"\s*(?:&&|;)\s*", line) if x]
        outputs = []
        for seg in segments:
            out, ex = await self._run(s, seg)
            if out:
                outputs.append(out)
            if ex:
                return "\n".join(outputs), True
        out = "\n".join(outputs)
        s.history.append([line, out])
        return out, False

    async def _run(self, s, line):
        if line.startswith("sudo ") and len(line) > 5:
            line = line[5:].strip()
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if not parts:
            return "", False
        cmd, args = parts[0], parts[1:]
        res = self._builtin(s, cmd, args)
        if res is not None:
            return res
        return await self.backend.generate(s, line), False

    # ------------------------------------------------------------- builtins
    def _touch_honeytoken(self, s, path):
        if path in HONEYTOKENS:
            self.log.event(s, "honeytoken_access", path=path)

    def _builtin(self, s, cmd, args):
        fs = s.fs
        if cmd in ("exit", "logout", "quit"):
            return "logout", True
        if cmd == "pwd":
            return s.cwd, False
        if cmd == "whoami":
            return s.user, False
        if cmd == "id":
            return ("uid=0(root) gid=0(root) groups=0(root)" if s.user == "root"
                    else f"uid=1000({s.user}) gid=1000({s.user}) groups=1000({s.user})"), False
        if cmd == "hostname":
            return s.hostname, False
        if cmd == "uname":
            return (UNAME_A.format(h=s.hostname) if args and args[0].startswith("-a") else "Linux"), False
        if cmd == "clear":
            return "\x1b[2J\x1b[H", False
        if cmd == "history":
            return "\n".join(f"{i + 1:>5}  {c}" for i, (c, _) in enumerate(s.history)), False
        if cmd == "cd":
            target = fs.norm(s.cwd, args[0] if args else "~", s.home)
            if fs.isdir(target):
                s.cwd = target
                return "", False
            return f"bash: cd: {args[0]}: No such file or directory", False
        if cmd == "ls":
            return self._ls(s, args), False
        if cmd == "cat" and args:
            outs = []
            for a in args:
                p = fs.norm(s.cwd, a, s.home)
                if fs.isfile(p):
                    self._touch_honeytoken(s, p)
                    outs.append(fs.files[p].rstrip("\n"))
                elif fs.isdir(p):
                    outs.append(f"cat: {a}: Is a directory")
                else:
                    outs.append(f"cat: {a}: No such file or directory")
            return "\n".join(outs), False
        if cmd == "mkdir" and args:
            for a in [x for x in args if not x.startswith("-")]:
                fs.mkdir(fs.norm(s.cwd, a, s.home))
            return "", False
        if cmd == "touch" and args:
            for a in args:
                p = fs.norm(s.cwd, a, s.home)
                if not fs.isfile(p):
                    fs.write(p, "")
            return "", False
        if cmd == "rm" and args:
            for a in [x for x in args if not x.startswith("-")]:
                p = fs.norm(s.cwd, a, s.home)
                if fs.isfile(p):
                    fs.remove(p)
                elif not fs.isdir(p):
                    return f"rm: cannot remove '{a}': No such file or directory", False
            return "", False
        if cmd == "echo":
            for op in (">>", ">"):
                if op in args:
                    i = args.index(op)
                    if i + 1 < len(args):
                        fs.write(fs.norm(s.cwd, args[i + 1], s.home), " ".join(args[:i]) + "\n", append=(op == ">>"))
                        return "", False
            return " ".join(args), False
        return None

    def _ls(self, s, args):
        fs = s.fs
        flags = "".join(a for a in args if a.startswith("-"))
        paths = [a for a in args if not a.startswith("-")] or ["."]
        long_, all_ = "l" in flags, "a" in flags
        out = []
        for p in paths:
            ap = fs.norm(s.cwd, p, s.home)
            if fs.isfile(ap):
                names, base = [posixpath.basename(ap)], posixpath.dirname(ap)
            elif fs.isdir(ap):
                names, base = fs.listdir(ap), ap
                if not all_:
                    names = [n for n in names if not n.startswith(".")]
                else:
                    names = [".", ".."] + names
            else:
                out.append(f"ls: cannot access '{p}': No such file or directory")
                continue
            if len(paths) > 1:
                out.append(f"{p}:")
            if long_:
                for n in names:
                    full = posixpath.join(base, n)
                    isd = full in fs.dirs or n in (".", "..")
                    size = 4096 if isd else len(fs.files.get(full, ""))
                    out.append(f"{'drwxr-xr-x' if isd else '-rw-r--r--'} 1 root root {size:>6} Oct 12 09:14 {n}")
            else:
                out.append("  ".join(names))
        return "\n".join(out)
