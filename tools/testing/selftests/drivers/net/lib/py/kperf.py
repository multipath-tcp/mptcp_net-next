# SPDX-License-Identifier: GPL-2.0

"""Run and parse kperf network performance measurements."""

import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass

from lib.py import cmd, ksft_pr, rand_port, wait_port_listen


_SECTION_RE = re.compile(r"==\s+(Source|Target)\b")
_RATE_RE = re.compile(r"\b(Tx|Rx)\s*([0-9]+(?:\.[0-9]+)?)\s+Gbps\b")


@dataclass
class KperfResult:
    """Aggregate throughput (Gbps) of both endpoints."""

    source_throughput: float
    target_throughput: float


class KperfRunner:
    """Manage kperf servers and run measurements between test endpoints."""

    def __init__(self, env):
        self.env = env
        self._pid_prefix = f"/tmp/ksft-kperf-{uuid.uuid4().hex[:8]}"
        self._port = rand_port()
        self._started = []
        env.require_cmd("kperf-client", local=True)
        env.require_cmd("kperf-server", local=True, remote=True)

    def _pid_file(self, remote):
        # The hosts may share /tmp (netns), and kperf-server kills the
        # process named in an existing PID file.
        return f"{self._pid_prefix}-{'remote' if remote else 'local'}.pid"

    def _log_file(self, remote):
        return f"{self._pid_prefix}-{'remote' if remote else 'local'}.log"

    def _server(self, remote, kill=False):
        host = self.env.remote if remote else None
        address = self.env.remote_addr if remote else self.env.addr
        args = ["kperf-server", "--pid-file", self._pid_file(remote)]
        if kill:
            args.append("--kill")
        else:
            args += ["--addr", address, "--port", str(self._port)]
            # The output of a daemon is lost, unless it can log
            usage = cmd("kperf-server --help", host=host, fail=False)
            if "--log-file" in usage.stdout + usage.stderr:
                args += ["--log-file", self._log_file(remote)]
        return cmd(shlex.join(args) if remote else args, host=host,
                   fail=not kill)

    def _print_logs(self):
        """Print the end of the logs of the servers, to tell why the client
        failed.
        """
        for remote in self._started:
            host = self.env.remote if remote else None
            args = ["tail", "-n", "30", self._log_file(remote)]
            log = cmd(shlex.join(args) if remote else args, host=host,
                      fail=False)
            if log.stdout.strip():
                name = "remote" if remote else "local"
                ksft_pr(f"kperf-server log ({name}):\n{log.stdout.strip()}")

    def __enter__(self):
        try:
            for remote in (False, True):
                self._server(remote)
                self._started.append(remote)
            wait_port_listen(self._port)
            wait_port_listen(self._port, host=self.env.remote)
        except Exception:
            self.close()
            raise
        return self

    def close(self):
        """Stop the started kperf servers, which waits for their sessions."""
        failures = []
        while self._started:
            remote = self._started.pop()
            command = self._server(remote, kill=True)
            if command.ret:
                failures.append(command)
            host = self.env.remote if remote else None
            args = ["rm", "-f", self._log_file(remote)]
            cmd(shlex.join(args) if remote else args, host=host, fail=False)
        if failures:
            details = "\n".join(str(command) for command in failures)
            raise RuntimeError(f"failed to stop kperf server(s)\n{details}")

    def __exit__(self, _exc_type, _exc_value, _exc_tb):
        self.close()

    def run(self, client_args=()):
        """Run kperf and return its KperfResult."""
        argv = ["kperf-client", "--src", self.env.remote_addr,
                "--dst", self.env.addr, "--src-svc", str(self._port),
                "--dst-svc", str(self._port)]
        argv += [str(arg) for arg in client_args]
        command = cmd(argv, background=True)
        try:
            command.process(terminate=False, fail=False, timeout=300)
        except subprocess.TimeoutExpired as error:
            command.proc.kill()
            command.process(terminate=False, fail=False)
            self._print_logs()
            raise RuntimeError(f"kperf client timed out\n{command!r}") \
                from error
        if command.ret:
            self._print_logs()
            raise RuntimeError(
                f"kperf client exited with status {command.ret}\n{command!r}")

        try:
            result = self.parse(command.stdout + "\n" + command.stderr)
        except ValueError:
            ksft_pr(command)
            self._print_logs()
            raise

        return result

    @staticmethod
    def parse(output):
        """Parse human-readable kperf client output."""
        throughput = {"Source": [], "Target": []}
        section = None

        for line in output.splitlines():
            match = _SECTION_RE.search(line)
            if match:
                section = match.group(1)
                continue
            if section is None:
                continue

            match = _RATE_RE.search(line)
            if match:
                direction, value = match.groups()
                if (section, direction) in (("Source", "Tx"),
                                             ("Target", "Rx")):
                    throughput[section].append(float(value))

        if not all(throughput.values()):
            raise ValueError("incomplete kperf result")

        return KperfResult(sum(throughput["Source"]),
                           sum(throughput["Target"]))
