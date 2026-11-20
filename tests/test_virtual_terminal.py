from mirage.emulation.terminal import VirtualTerminal


def test_virtual_terminal_returns_fabricated_linux_identity() -> None:
    terminal = VirtualTerminal()
    assert terminal.execute("whoami") == "www-data"
    assert terminal.execute("hostname") == "intranet.example.test"
    assert terminal.execute("pwd") == "/var/www"
    assert "Ubuntu" in terminal.execute("uname -a")


def test_virtual_filesystem_contains_only_fabricated_files() -> None:
    terminal = VirtualTerminal()
    assert "Internal Staff Portal" in terminal.execute("cat /var/www/html/index.html")
    passwd = terminal.execute("cat /etc/passwd")
    assert "www-data" in passwd
    assert "deploy" in passwd
    assert "root:" in passwd


def test_virtual_directory_navigation_is_instance_local() -> None:
    first = VirtualTerminal()
    second = VirtualTerminal()
    assert first.execute("cd /home/deploy") == ""
    assert first.execute("pwd") == "/home/deploy"
    assert second.execute("pwd") == "/var/www"
    assert "Deployment notes" in first.execute("cat README.txt")


def test_virtual_listing_and_process_table_are_deterministic() -> None:
    terminal = VirtualTerminal()
    assert "html" in terminal.execute("ls")
    assert "nginx: worker process" in terminal.execute("ps aux")


def test_unknown_commands_and_unsupported_options_are_not_executed() -> None:
    terminal = VirtualTerminal()
    assert terminal.execute("sudo id").endswith("command not found")
    assert terminal.execute("python -c 'print(1)'").endswith("command not found")
    assert terminal.execute("ls --help") == "ls: unsupported option"


def test_shell_operators_and_expansion_are_rejected() -> None:
    terminal = VirtualTerminal()
    for command in (
        "whoami; id",
        "cat /etc/passwd | sh",
        "cat /etc/passwd > /tmp/out",
        "echo $HOME",
        "whoami && hostname",
        "cat /etc/passwd `id`",
    ):
        assert "not supported" in terminal.execute(command)


def test_path_traversal_and_real_host_paths_are_not_accessible() -> None:
    terminal = VirtualTerminal()
    assert "No such file" in terminal.execute("cat ../../etc/shadow")
    assert "No such file" in terminal.execute("cat /proc/self/environ")
    assert "No such file" in terminal.execute("cat /etc/shadow")
    assert "etc" in terminal.execute("ls /")


def test_input_limits_and_invalid_quotes_fail_safely() -> None:
    terminal = VirtualTerminal()
    assert terminal.execute("x" * 513) == "mirage: input too long"
    assert terminal.execute("cat 'unterminated") == "mirage: invalid quoting"
    assert terminal.execute("cat " + " ".join(["x"] * 17)) == "mirage: too many arguments"


def test_help_and_clear_are_local_terminal_operations() -> None:
    terminal = VirtualTerminal()
    assert "Available commands" in terminal.execute("help")
    assert terminal.execute("clear") == ""



def test_simulate_terminal_cli_exits_cleanly(monkeypatch, capsys) -> None:
    from mirage import cli

    commands = iter(["whoami", "cat /etc/hostname", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(commands))
    assert cli.main(["simulate-terminal"]) == 0
    output = capsys.readouterr().out
    assert "MIRAGE virtual terminal" in output
    assert "www-data" in output
    assert "intranet.example.test" in output
