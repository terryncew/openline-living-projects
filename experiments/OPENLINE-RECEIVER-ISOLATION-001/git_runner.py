"""OpenLine Production Isolation — Sanitized Git Runner and Repository Hygiene Verifier.

Implements Section 2.1, 4.3, and 4.4 of Astra's Production Isolation Blueprint:
- Strips all inherited `GIT_*`, `LD_*`, `PYTHON*`, `BASH_ENV`, `ENV` environment variables.
- Pins `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_ALLOW_PROTOCOL=none`, `core.hooksPath=<empty_hooks_dir>`, `protocol.allow=never`,
  `core.fsmonitor=false`, `core.fsync=all`, `core.symlinks=false`.
- Audits bare Git repositories for symlinks, ownership, executable hooks, and dangerous config directives.
"""
from __future__ import annotations

from pathlib import Path
import os
import stat
import subprocess


class GitRunnerError(RuntimeError):
    """Raised when a sanitized Git command fails or repository hygiene is violated."""


DANGEROUS_GIT_CONFIG_KEYS = (
    "core.fsmonitor",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "credential.helper",
    "uploadpack.packobjectshook",
)


class SanitizedGitRunner:
    """Executes Git commands with stripped environment and pinned safe configuration flags."""

    def __init__(self, empty_hooks_dir: Path | str, *, home_dir: Path | str | None = None):
        self.empty_hooks_dir = Path(empty_hooks_dir).resolve()
        self.home_dir = Path(home_dir).resolve() if home_dir else self.empty_hooks_dir.parent
        self.ensure_empty_hooks_dir()

    def ensure_empty_hooks_dir(self) -> None:
        if self.empty_hooks_dir.is_symlink():
            raise GitRunnerError("empty_hooks_dir_symlink_forbidden")
        self.empty_hooks_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for item in self.empty_hooks_dir.iterdir():
            raise GitRunnerError(f"empty_hooks_dir_not_empty:{item.name}")

    def clean_env(self) -> dict[str, str]:
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home_dir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_ALLOW_PROTOCOL": "none",
        }

    def base_git_flags(self) -> list[str]:
        self.ensure_empty_hooks_dir()
        return [
            "git",
            "-c", f"core.hooksPath={self.empty_hooks_dir}",
            "-c", "protocol.allow=never",
            "-c", "core.fsmonitor=false",
            "-c", "core.fsync=all",
            "-c", "core.symlinks=false",
            "-c", "filter.lfs.clean=",
            "-c", "filter.lfs.smudge=",
            "-c", "filter.lfs.process=",
        ]

    def run(
        self,
        *args: str,
        cwd: Path | str | None = None,
        timeout: float = 30.0,
        check: bool = True,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess:
        cmd_list = self.base_git_flags() + [str(a) for a in args]
        p = subprocess.run(
            cmd_list,
            cwd=str(cwd) if cwd is not None else None,
            env=self.clean_env(),
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and p.returncode != 0:
            raise GitRunnerError(f"git_exit_{p.returncode}:{args[:3]}:{p.stderr[:400].strip()}")
        return p

    def verify_bare_repo_hygiene(self, repo_path: Path | str, *, expected_uid: int | None = None) -> list[str]:
        repo = Path(repo_path)
        reasons: list[str] = []
        if repo.is_symlink():
            return ["accepted_git_symlink_forbidden"]
        if not repo.is_dir():
            return ["accepted_git_missing"]
        try:
            self.ensure_empty_hooks_dir()
        except GitRunnerError as exc:
            reasons.append(str(exc))

        for sub in [repo, *repo.rglob("*")]:
            if sub.is_symlink():
                reasons.append("accepted_git_contains_symlink")
                break
            st = sub.stat()
            if expected_uid is not None and st.st_uid != expected_uid:
                reasons.append("accepted_git_not_receiver_owned")
            if st.st_mode & 0o002:
                reasons.append("accepted_git_world_writable")

        hooks_dir = repo / "hooks"
        if hooks_dir.is_dir():
            for h in hooks_dir.iterdir():
                if h.name.endswith(".sample"):
                    continue
                if h.is_file() and (h.stat().st_mode & 0o111):
                    reasons.append(f"executable_repo_hook_forbidden:{h.name}")

        p_bare = self.run("--git-dir", str(repo), "rev-parse", "--is-bare-repository", check=False)
        if p_bare.returncode != 0 or p_bare.stdout.strip() != "true":
            reasons.append("accepted_git_not_bare")

        p_cfg = self.run("--git-dir", str(repo), "config", "--local", "--list", check=False)
        if p_cfg.returncode == 0:
            for line in p_cfg.stdout.splitlines():
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k_low = k.strip().lower()
                v_strip = v.strip()
                if k_low in DANGEROUS_GIT_CONFIG_KEYS and v_strip and v_strip.lower() not in ("false", "0", "none"):
                    reasons.append(f"dangerous_git_config:{k_low}")
                if k_low.startswith("alias.") or (k_low.startswith("filter.") and v_strip):
                    reasons.append(f"dangerous_git_config:{k_low}")

        return sorted(set(reasons))
