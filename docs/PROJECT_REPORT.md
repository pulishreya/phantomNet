# Internship Project Report

| | |
|---|---|
| **Project Title** | PhantomNet: Generative Cyber-Deception (LLM Honeypots) |
| **Intern Name** | Puli Shreya |
| **Role** | Associate L1 Intern |
| **Domain** | Generative AI |
| **Organization** | Infotact Solutions |
| **Internship Period** | 12 October 2026 - 12 November 2026 |
| **Date of Submission** | 5 November 2026 |

---

# PhantomNet: Generative Cyber-Deception (LLM Honeypots)

## 1. Abstract
Honeypots are decoy systems that lure attackers so their behaviour can be studied. Classic low/medium-interaction
honeypots use scripted responses and are easy to fingerprint. PhantomNet uses a Large Language Model (LLM) to generate
realistic shell output dynamically, backed by a stateful fake filesystem for consistency. It logs all attacker activity,
maps commands to MITRE ATT&CK techniques, plants honeytokens and resists prompt injection aimed at the LLM.

## 2. Problem Statement
- Static honeypots answer unknown commands identically, which reveals them.
- Attackers automate reconnaissance and fingerprint known honeypot software.
- Defenders need structured intelligence (TTPs, credentials, tooling) with minimal risk.

## 3. Objectives
1. Build an interactive honeypot that convincingly emulates a Linux server.
2. Use an LLM to answer arbitrary commands while staying consistent within a session.
3. Capture and analyse attacker behaviour (credentials, commands, ATT&CK techniques).
4. Keep the system safe: no real execution, no real downloads, resistant to prompt injection.

## 4. System Design
- **Honeypot server** (`honeypot.py`): asyncio TCP server, fake login, MOTD and prompt, session and idle timeouts.
- **Engine** (`engine.py`): deterministic builtins first, LLM for the rest; handles `&&` and `;`.
- **Session state** (`session.py`): mutable `FakeFS`, working directory, user, history. This is the source of consistency.
- **LLM layer** (`llm.py`): `MockBackend`, `AnthropicBackend`, `OllamaBackend`; strict system prompt; output sanitiser; fallback to mock.
- **Telemetry** (`logger.py`, `mitre.py`, `dashboard.py`): JSONL + SQLite, technique tagging, live dashboard.

**Why hybrid:** common commands (`ls`, `cat`, `cd`) must be perfectly consistent and cheap, so they are deterministic.
Rare commands are where scripted honeypots fail, so those go to the LLM with session context.

## 5. Security Considerations
| Threat | Mitigation |
|---|---|
| Honeypot abused to attack others | No command is executed; `wget`/`curl` always fail |
| Prompt injection against the LLM | Regex detection, logged as an event, text never reaches the LLM; system prompt marks commands as data |
| LLM reveals it is an AI | System prompt forbids it; sanitiser strips markdown; mock fallback |
| Resource abuse | Session cap, idle timeout, output length limit |
| XSS via log data in dashboard | All attacker strings HTML-escaped |

## 6. Implementation
Python 3 standard library only (asyncio, sqlite3, http.server, urllib). Unit tests cover ATT&CK tagging, filesystem state,
exit handling, injection containment, honeytoken alerts and download safety.

## 7. Results
A scripted attacker ran reconnaissance, credential harvesting, a payload download and history clearing. PhantomNet stayed
consistent throughout, recorded 24 events, flagged 1 honeytoken access and 1 prompt-injection attempt, and tagged
techniques including T1033, T1082, T1083, T1003.008, T1105, T1222.002, T1057, T1049 and T1070.003.

## 8. Limitations
Telnet-style transport rather than SSH; limited shell grammar; LLM latency can be a tell; no filesystem persistence across sessions.

## 9. Future Work
SSH via asyncssh; HTTP/MySQL/FTP decoys; response caching; IOC extraction and STIX/TAXII export; Grafana/ELK dashboards;
adaptive personas; evaluation against honeypot-fingerprinting tools.

## 10. Conclusion
Generative deception raises the cost of reconnaissance for attackers and gives defenders richer intelligence. PhantomNet
shows a practical, safe architecture that combines deterministic state with LLM flexibility.

## References
- MITRE ATT&CK - https://attack.mitre.org
- Cowrie SSH/Telnet honeypot - https://github.com/cowrie/cowrie
