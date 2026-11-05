"""Per-attacker session state, including a mutable fake filesystem.

Keeping state here is what makes the deception *consistent*: if the attacker
creates a file, it must still exist on the next command.
"""
import posixpath
import time
import uuid
from dataclasses import dataclass, field


def base_files(hostname):
    return {
        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
            "deploy:x:1001:1001::/home/deploy:/bin/bash\n"
        ),
        "/etc/shadow": (
            "root:$6$Xk2pQ9aB$FAKEHASHFAKEHASHFAKEHASHFAKEHASHFAKEHASH:19650:0:99999:7:::\n"
            "admin:$6$m4Tz81Qe$DECOYHASHDECOYHASHDECOYHASHDECOYHASHDECOY:19650:0:99999:7:::\n"
        ),
        "/etc/hostname": hostname + "\n",
        "/etc/os-release": (
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\n'
        ),
        "/root/notes.txt": "TODO: rotate db creds before audit\nbackup job: /root/backup.sql.gz (nightly)\n",
        "/root/backup.sql.gz": "(binary data)",
        "/root/.bash_history": "mysql -u dbadmin -p\nsystemctl restart apache2\nvim /var/www/html/config.php.bak\n",
        "/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EDECOYKEYDECOYKEY ops@jump-01\n",
        "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
        "/var/www/html/config.php.bak": (
            "<?php\n$db_host = '10.0.2.15';\n$db_user = 'dbadmin';\n$db_pass = 'Summer2023!';\n"
        ),
        "/var/log/auth.log": "",
    }


HONEYTOKENS = {
    "/var/www/html/config.php.bak",
    "/root/notes.txt",
    "/root/backup.sql.gz",
    "/root/.ssh/authorized_keys",
    "/etc/shadow",
}


class FakeFS:
    def __init__(self, hostname):
        self.files = base_files(hostname)
        self.dirs = {"/", "/bin", "/home", "/tmp", "/usr", "/opt", "/var", "/var/log",
                     "/home/admin", "/home/deploy"}
        for f in list(self.files):
            self._add_parents(f)

    def _add_parents(self, path):
        d = posixpath.dirname(path)
        while d not in ("/", ""):
            self.dirs.add(d)
            d = posixpath.dirname(d)

    def norm(self, cwd, p, home):
        if p == "~" or p.startswith("~/"):
            p = home + p[1:]
        if not p.startswith("/"):
            p = cwd.rstrip("/") + "/" + p
        return posixpath.normpath(p)

    def isfile(self, p):
        return p in self.files

    def isdir(self, p):
        return p in self.dirs

    def listdir(self, path):
        names = {posixpath.basename(x) for x in list(self.files) + list(self.dirs)
                 if x != path and posixpath.dirname(x) == path}
        return sorted(names)

    def write(self, path, content, append=False):
        if path in self.files and append:
            self.files[path] += content
        else:
            self.files[path] = content
        self._add_parents(path)

    def mkdir(self, path):
        self.dirs.add(path)
        self._add_parents(path)

    def remove(self, path):
        self.files.pop(path, None)


@dataclass
class Session:
    ip: str
    port: int = 0
    hostname: str = "srv-db-01"
    user: str = "root"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started: float = field(default_factory=time.time)
    history: list = field(default_factory=list)  # [[command, output], ...]
    cwd: str = ""
    fs: FakeFS = None

    def __post_init__(self):
        self.fs = FakeFS(self.hostname)
        self.cwd = self.home

    @property
    def home(self):
        return "/root" if self.user == "root" else f"/home/{self.user}"

    def prompt(self):
        sym = "#" if self.user == "root" else "$"
        shown = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.hostname}:{shown}{sym} "

    def transcript(self, n=10):
        return self.history[-n:]
