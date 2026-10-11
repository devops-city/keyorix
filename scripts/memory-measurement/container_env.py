"""container_env.py — build/run/reset the real keyorix-server container this
harness measures against, matching server/Dockerfile and the shipped Helm
chart's default storage backend (SQLite, config.storage.type: local).

Every measurement this harness produces depends on the container runtime's
own resource-accounting behavior (see README.md's Portability section) --
this module exists to make that setup reproducible, not to hide it.
"""

import os
import shutil
import subprocess
import tempfile
import time

IMAGE_TAG = "keyorix-server-memory-measurement"

_KEYORIX_YAML = """\
storage:
  type: local
  database:
    path: data/keyorix.db
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: 8080
locale:
  language: en
  fallback_language: en
"""

ADMIN_PASSWORD = "Zk9-Repro-Harness-Bootstrap"  # policy: upper+digit, and must not overlap username/email/display name
MASTER_PASSWORD = "measurement-harness-master-pass"
BOOTSTRAP_TOKEN = "measurement-harness-bootstrap-token"


def repo_root() -> str:
    out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True)
    return out.strip()


def build_image():
    root = repo_root()
    subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "-f", os.path.join(root, "server", "Dockerfile"), root],
        check=True,
    )


class Workdir:
    """A fresh keys/+data/ + keyorix.yaml on disk, torn down on exit."""

    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="keyorix-memory-measurement-")
        os.makedirs(os.path.join(self.path, "keys"), exist_ok=True)
        os.makedirs(os.path.join(self.path, "data"), exist_ok=True)
        self._open_mounts_to_container_user()
        with open(os.path.join(self.path, "keyorix.yaml"), "w") as f:
            f.write(_KEYORIX_YAML)

    def _open_mounts_to_container_user(self):
        """The image runs as uid 1001. On a Linux Docker host a bind mount keeps the
        host user's ownership (Docker Desktop maps it away), so without this the
        server cannot create keyorix.db.server.lock in data/ and never starts. The
        parent mkdtemp() directory is 0700, so no other host user can reach these."""
        for sub in ("keys", "data"):
            os.chmod(os.path.join(self.path, sub), 0o777)

    def reset_data(self):
        """Wipe the DB/key material so the next container boots fresh,
        without tearing down and recreating the whole temp directory."""
        for sub in ("keys", "data"):
            d = os.path.join(self.path, sub)
            shutil.rmtree(d)
            os.makedirs(d)
        self._open_mounts_to_container_user()

    def cleanup(self):
        shutil.rmtree(self.path, ignore_errors=True)


def run_container(name: str, workdir: Workdir, host_port: int, memory_cap: str = None,
                   with_admin_bootstrap: bool = True) -> None:
    """Start a fresh container named `name`, publishing host_port -> 8080.
    memory_cap, if given, is passed straight to `docker run --memory`
    (e.g. "512m")."""
    subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)
    # `docker rm -f` returning doesn't guarantee the host port it held is
    # immediately rebindable -- back-to-back oom_check/sustained scenarios
    # reusing the same name+port in quick succession (as the matrix runner
    # does) intermittently failed to become healthy within their boot
    # timeout, traced to exactly this: the new container starts, but its
    # publish binding races the just-removed container's own teardown. A
    # short, fixed settle avoids the race without needing to detect it.
    time.sleep(3)
    cmd = [
        "docker", "run", "-d", "--name", name,
        "-v", f"{workdir.path}/keyorix.yaml:/app/keyorix.yaml:ro",
        "-v", f"{workdir.path}/keys:/app/keys",
        "-v", f"{workdir.path}/data:/app/data",
        "-e", f"KEYORIX_MASTER_PASSWORD={MASTER_PASSWORD}",
        "-p", f"{host_port}:8080",
    ]
    if with_admin_bootstrap:
        cmd += [
            "-e", f"KEYORIX_ADMIN_PASSWORD={ADMIN_PASSWORD}",
            "-e", f"KEYORIX_BOOTSTRAP_TOKEN={BOOTSTRAP_TOKEN}",
        ]
    if memory_cap:
        cmd += ["--memory", memory_cap]
    cmd.append(IMAGE_TAG)
    subprocess.run(cmd, check=True, capture_output=True)


def wait_healthy(base_url: str, container: str = None, timeout_s: int = 60):
    import urllib.request
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            # base_url is always this script's own f"http://localhost:{PORT}" (matrix_runner.py, the
            # container this same process just started) -- no external input reaches this URL.
            urllib.request.urlopen(base_url + "/health", timeout=2)  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            return
        except Exception as e:
            last_err = e
            # If the container itself already exited, waiting out the rest
            # of timeout_s just to report the same network error is
            # pointless -- fail immediately with the real reason (crash,
            # or OOM-killed before ever becoming healthy) instead.
            if container is not None:
                try:
                    running = subprocess.check_output(
                        ["docker", "inspect", "-f", "{{.State.Running}}", container], text=True
                    ).strip()
                    if running != "true":
                        exit_code = subprocess.check_output(
                            ["docker", "inspect", "-f", "{{.State.ExitCode}}", container], text=True
                        ).strip()
                        oom = subprocess.check_output(
                            ["docker", "inspect", "-f", "{{.State.OOMKilled}}", container], text=True
                        ).strip()
                        raise RuntimeError(
                            f"container {container} exited before becoming healthy "
                            f"(exit code {exit_code}, OOMKilled={oom}): {e}"
                        )
                except subprocess.CalledProcessError:
                    pass  # container may not exist yet this early -- keep polling
            time.sleep(1)
    raise TimeoutError(f"server never became healthy within {timeout_s}s: {last_err}")


def wait_admin_ready(client, max_attempts: int = 4, retry_delay_s: int = 3) -> str:
    """/health passing only means the HTTP listener is up -- entrypoint.sh's
    admin-bootstrap POST /system/init runs AFTER that, asynchronously, so a
    login attempted immediately after wait_healthy() can 401 against an
    admin user that doesn't exist yet.

    Deliberately NOT a tight retry-until-timeout poll: the login endpoint
    has per-account brute-force lockout (max_attempts=5 within a 15-minute
    window, server default), and a 1s-interval poll blows through that
    budget in 5 seconds flat, triggering a 429 that then locks this
    harness out of its own freshly-booted container for 15 minutes. A small
    number of attempts spaced 3s apart comfortably covers the real
    bootstrap latency (observed ~250-550ms in this harness's own manual
    predecessor) while staying well under the lockout threshold."""
    last_err = None
    for _ in range(max_attempts):
        try:
            return client.login("admin", ADMIN_PASSWORD)
        except Exception as e:
            last_err = e
            time.sleep(retry_delay_s)
    raise TimeoutError(f"admin login never succeeded after {max_attempts} attempts: {last_err}")


def remove_container(name: str):
    subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)


def remove_image():
    subprocess.run(["docker", "rmi", IMAGE_TAG], check=False, capture_output=True)
