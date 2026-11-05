"""Lightweight MITRE ATT&CK tagger for attacker shell commands."""
import re

RULES = [
    (r"\b(wget|curl|tftp|scp|ftp)\b", "T1105", "Ingress Tool Transfer"),
    (r"/etc/(passwd|shadow)", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    (r"\b(uname|lscpu|cat\s+/etc/os-release|df|free)\b", "T1082", "System Information Discovery"),
    (r"\b(whoami|id|w|who|last)\b", "T1033", "System Owner/User Discovery"),
    (r"\b(ifconfig|ip\s+a|ip\s+addr|route|hostname)\b", "T1016", "System Network Configuration Discovery"),
    (r"\b(netstat|ss)\b", "T1049", "System Network Connections Discovery"),
    (r"\b(ps|top|pgrep)\b", "T1057", "Process Discovery"),
    (r"\b(ls|find|locate|tree)\b", "T1083", "File and Directory Discovery"),
    (r"\bcrontab\b|/etc/cron", "T1053.003", "Scheduled Task/Job: Cron"),
    (r"authorized_keys|ssh-keygen", "T1098.004", "Account Manipulation: SSH Authorized Keys"),
    (r"history\s+-c|rm\s+.*(\.bash_history|/var/log)|unset\s+HISTFILE", "T1070.003", "Indicator Removal: Clear Command History"),
    (r"\bchmod\s+(\+x|[0-7]*7[0-7]*)", "T1222.002", "File Permissions Modification"),
    (r"\b(nc|ncat|netcat)\b|bash\s+-i|/dev/tcp/", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r"base64\s+(-d|--decode)", "T1140", "Deobfuscate/Decode Files or Information"),
    (r"\b(sudo|su)\b", "T1548.003", "Abuse Elevation Control: Sudo"),
    (r"\b(pkill|kill|killall|systemctl\s+stop|service\s+\S+\s+stop)\b", "T1489", "Service Stop"),
    (r"\b(nmap|masscan|zmap)\b", "T1046", "Network Service Discovery"),
    (r"\b(xmrig|minerd|stratum\+tcp)\b", "T1496", "Resource Hijacking"),
]
_COMPILED = [(re.compile(p, re.I), i, n) for p, i, n in RULES]


def tag(command: str):
    seen, out = set(), []
    for rx, tid, name in _COMPILED:
        if rx.search(command) and tid not in seen:
            seen.add(tid)
            out.append({"id": tid, "name": name})
    return out
