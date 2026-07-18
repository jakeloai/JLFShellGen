# JLFShellGen

> Designed by **jakelo.ai** · Coded with AI assistance

A command-line tool that generates shell commands and web shells for security testing. You pick the type, set your IP and port, and it outputs the payload strings.

---

## What it does

You give it:
- A payload type (reverse shell, bind shell, web shell, download & execute, TTY upgrade, pivoting, post-exploitation, SSRF)
- Your listener IP and port
- Optional filters (OS, shell type, language)

It outputs the command strings. Optionally with encoding (base64, URL, hex) or obfuscation variants.

That's it. No network activity. No callbacks. Just text generation.

---

## Installation

```bash
git clone https://github.com/jakeloai/JLFShellGen.git
cd JLFShellGen
go build -o jlfshellgen .
```

Requires Go 1.18+.

---

## How to use

**Reverse shell:**
```bash
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444
```

**Web shell (PHP):**
```bash
./jlfshellgen -type webshell -lang php
```

**With encoding variants:**
```bash
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444 -encode
```

**Generate everything:**
```bash
./jlfshellgen -type all -lhost 10.0.0.1 -lport 4444 -o payloads.txt
```

---

## Payload types

| Type | What it generates |
|---|---|
| `reverse` | Commands that connect back to your listener |
| `bind` | Commands that open a listening port on the target |
| `webshell` | Web uploadable shells (PHP, JSP, ASP, etc.) |
| `download` | Commands that fetch and execute a remote file |
| `tty` | Commands to upgrade a basic shell to interactive |
| `pivot` | SSH/socat/chisel tunnel commands |
| `post` | Enumeration one-liners (Linux/Windows) |
| `ssrf` | Internal service URLs and cloud metadata endpoints |

---

## Output formats

```bash
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444 -format plain    # Human readable (default)
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444 -format raw      # Payloads only
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444 -format json     # JSON array
./jlfshellgen -type reverse -lhost 10.0.0.1 -lport 4444 -format markdown # Markdown document
```

---

## Options

| Flag | Description |
|---|---|
| `-type` | Payload type (required) |
| `-lhost` | Your IP address |
| `-lport` | Your port number |
| `-os` | Filter by OS: linux, windows, macos, all |
| `-shell` | Filter by shell: bash, python, powershell, etc. |
| `-lang` | Filter webshell language: php, jsp, asp, etc. |
| `-encode` | Include base64, URL, and hex variants |
| `-obfuscate` | Include basic obfuscation variants |
| `-format` | Output format: plain, raw, json, markdown |
| `-o` | Output file (default: stdout) |

---

## Note

This tool generates text strings only. It does not execute anything, does not connect anywhere, and does not phone home. What you do with the output is your responsibility. Only use on systems you own or have explicit permission to test.

---

## License

GNU General Public License v3.0 (GPL-3.0) © jakelo.ai
