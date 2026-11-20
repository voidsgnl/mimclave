"""A bounded terminal-like interpreter backed only by fabricated in-memory data.

This module never invokes a shell, subprocess, host filesystem, or network API.
It is a deterministic teaching/deception surface, not a real operating-system shell.
"""

import posixpath
import re
import shlex
from dataclasses import dataclass

MAX_COMMAND_LENGTH = 512
MAX_ARGUMENTS = 16
_FORBIDDEN_SYNTAX = re.compile(r"[|;&<>\x60$\n\r]")
VIRTUAL_HOSTNAME = "intranet.example.test"
VIRTUAL_USER = "www-data"

_VIRTUAL_FILES = {
    "/etc/hostname": f"{VIRTUAL_HOSTNAME}\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'VERSION_ID="22.04"\n'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "deploy:x:1001:1001:Deployment User:/home/deploy:/bin/bash\n"
        "backup:x:1002:1002:Backup User:/home/backup:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$decoy-root-hash:20420:0:99999:7:::\n"
        "www-data:!:20420:0:99999:7:::\n"
        "deploy:$6$decoy-deploy-hash:20420:0:99999:7:::\n"
    ),
    "/etc/gshadow": (
        "root:*:::\n"
        "shadow:*:::\n"
    ),
    "/root/.bash_history": "sudo -l\ncat /etc/shadow\n",
    "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
    "/var/www/html/index.html": (
        "<html><head><title>Intranet Portal</title></head>"
        "<body><h1>Internal Staff Portal</h1></body></html>\n"
    ),
    "/var/www/html/config.php": (
        "<?php\n"
        "// Application configuration (fabricated decoy data)\n"
        "$app_name = 'Intranet Portal';\n"
        "$db_host = 'db01.internal';\n"
        "$db_name = 'intranet';\n"
        "$db_user = 'portal_app';\n"
        "$db_password = 'REDACTED-DECOY-VALUE';\n"
    ),
    "/home/deploy/README.txt": (
        "Deployment notes\n"
        "================\n"
        "Application: intranet-portal\n"
        "Release channel: stable\n"
        "Last deployment: 2026-10-28\n"
    ),
    "/var/log/nginx/access.log": (
        '10.20.4.18 - - [20/Nov/2026:16:31:21 +0000] "GET / HTTP/1.1" 200 612\n'
        '10.20.4.18 - - [20/Nov/2026:16:31:37 +0000] "GET /login HTTP/1.1" 200 941\n'
    ),
}

_DIRECTORIES = {
    "/": ("etc", "home", "root", "var"),
    "/etc": ("hostname", "issue", "os-release", "passwd", "shadow", "gshadow"),
    "/root": (".bash_history",),
    "/home": ("backup", "deploy"),
    "/home/backup": (),
    "/home/deploy": ("README.txt",),
    "/var": ("log", "www"),
    "/var/log": ("nginx",),
    "/var/log/nginx": ("access.log",),
    "/var/www": ("html",),
    "/var/www/html": ("config.php", "index.html"),
}

# These paths exist in the simulated machine but are restricted to root.
# Keep this policy explicit: no host permission checks or filesystem calls occur.
_ROOT_ONLY_PATHS = frozenset({"/root", "/etc/shadow", "/etc/gshadow"})


def _permission_denied(path: str) -> bool:
    return path == "/root" or path.startswith("/root/") or path in _ROOT_ONLY_PATHS


_PROCESS_TABLE = (
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root           1  0.0  0.2  16892  9216 ?        Ss   Oct28   0:04 /sbin/init\n"
    "root         612  0.0  0.1  12840  5120 ?        Ss   Oct28   0:01 nginx: master process\n"
    "www-data     644  0.0  0.1  13240  5632 ?        S    Oct28   0:00 nginx: worker process\n"
    "www-data     645  0.0  0.1  13240  5632 ?        S    Oct28   0:00 nginx: worker process\n"
    "mysql        701  0.2  1.4 984320 58240 ?        Ssl  Oct28   0:19 /usr/sbin/mysqld\n"
)


@dataclass(slots=True)
class VirtualTerminal:
    """An isolated command interpreter with a per-instance virtual working directory."""

    hostname: str = VIRTUAL_HOSTNAME
    username: str = VIRTUAL_USER
    cwd: str = "/var/www"
    previous_cwd: str | None = None

    def execute(self, line: str) -> str:
        """Interpret one allowlisted command without evaluating host shell syntax."""
        if not isinstance(line, str) or not line.strip():
            return ""
        if len(line) > MAX_COMMAND_LENGTH:
            return "mirage: input too long"
        if _FORBIDDEN_SYNTAX.search(line):
            return "mirage: shell operators and expansions are not supported"

        try:
            tokens = shlex.split(line, posix=True)
        except ValueError:
            return "mirage: invalid quoting"
        if not tokens:
            return ""
        if len(tokens) > MAX_ARGUMENTS:
            return "mirage: too many arguments"

        command, *args = tokens
        if command == "help":
            return (
                "Available commands: help, whoami, hostname, pwd, id, uname, "
                "ls, cat, ps, cd, clear\n"
                "This is a simulated environment. Commands never run on the host."
            )
        if command == "whoami":
            return self.username
        if command == "hostname":
            return self.hostname
        if command == "pwd":
            return self.cwd
        if command == "id":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        if command == "uname":
            if args and args != ["-a"]:
                return "uname: unsupported option"
            return (
                "Linux intranet-web-01 5.15.0-91-generic #101-Ubuntu "
                "SMP x86_64 GNU/Linux"
            )
        if command == "ps":
            if args and args not in (["aux"], ["-ef"]):
                return "ps: unsupported option"
            return _PROCESS_TABLE
        if command == "clear":
            return ""
        if command == "cd":
            return self._change_directory(args)
        if command == "ls":
            return self._list_directory(args)
        if command == "cat":
            return self._read_files(args)
        return f"{command}: command not found"

    def _resolve(self, requested: str) -> str | None:
        if not requested or "\x00" in requested or requested.startswith("//"):
            return None
        candidate = (
            requested if requested.startswith("/")
            else posixpath.join(self.cwd, requested)
        )
        normalized = posixpath.normpath(candidate)
        # normpath resolves "." and ".." while keeping absolute paths rooted
        # at the simulated filesystem's "/" (it never consults the host FS).
        if not normalized.startswith("/") or normalized.startswith("//"):
            return None
        return normalized

    def _change_directory(self, args: list[str]) -> str:
        if len(args) > 1:
            return "cd: expected at most one path"
        target = args[0] if args else "/var/www"
        if target == "-":
            if self.previous_cwd is None:
                return "cd: OLDPWD not set"
            self.cwd, self.previous_cwd = self.previous_cwd, self.cwd
            return self.cwd

        resolved = self._resolve(target)
        if resolved is None:
            return f"cd: {target}: No such file or directory"
        if _permission_denied(resolved):
            return f"cd: {target}: Permission denied"
        if resolved not in _DIRECTORIES:
            return f"cd: {target}: No such file or directory"
        if resolved != self.cwd:
            self.previous_cwd = self.cwd
            self.cwd = resolved
        return ""

    def _list_directory(self, args: list[str]) -> str:
        paths = [arg for arg in args if not arg.startswith("-")]
        options = [arg for arg in args if arg.startswith("-")]
        if any(option not in ("-l", "-a", "-la", "-al") for option in options):
            return "ls: unsupported option"
        if len(paths) > 1:
            return "ls: one path at a time"
        target = self._resolve(paths[0]) if paths else self.cwd
        if target is None:
            return "ls: cannot access: No such file or directory"
        if _permission_denied(target):
            return f"ls: cannot open directory '{target}': Permission denied"
        if target not in _DIRECTORIES:
            return "ls: cannot access: No such file or directory"
        names = _DIRECTORIES[target]
        if "-l" in options or "-la" in options or "-al" in options:
            rows = []
            for name in names:
                entry = posixpath.join(target, name)
                if entry in _DIRECTORIES:
                    rows.append(
                        f"drwxr-xr-x 2 root root 4096 Nov 20 16:00 {name}"
                    )
                elif entry in ("/etc/shadow", "/etc/gshadow"):
                    rows.append(
                        f"-rw-r----- 1 root shadow  256 Nov 20 16:00 {name}"
                    )
                elif entry == "/root/.bash_history":
                    rows.append(
                        f"-rw------- 1 root root  128 Nov 20 16:00 {name}"
                    )
                else:
                    rows.append(
                        f"-rw-r--r-- 1 root root  128 Nov 20 16:00 {name}"
                    )
            return "\n".join(rows)
        return "  ".join(names)

    def _read_files(self, args: list[str]) -> str:
        if len(args) != 1:
            return "cat: expected exactly one virtual file path"
        target = self._resolve(args[0])
        if target is None:
            return f"cat: {args[0]}: No such file or directory"
        # Check restricted parent directories as well as the target itself.
        if _permission_denied(target):
            return f"cat: {args[0]}: Permission denied"
        if target not in _VIRTUAL_FILES:
            return f"cat: {args[0]}: No such file or directory"
        return _VIRTUAL_FILES[target].rstrip("\n")
