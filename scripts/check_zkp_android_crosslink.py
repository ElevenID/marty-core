"""Cross-link the real prover harness; this does not execute Android tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys


TARGETS = {
    "armv7-linux-androideabi": ("armv7a-linux-androideabi", "arm-linux-androideabi"),
    "aarch64-linux-android": ("aarch64-linux-android", "aarch64-linux-android"),
    "x86_64-linux-android": ("x86_64-linux-android", "x86_64-linux-android"),
}
NDK_VERSION = "28.2.13676358"


def inspect_artifact(executable: Path, target: str, readelf: Path) -> dict:
    elf_class, machine = {
        "armv7-linux-androideabi": (1, 40),
        "aarch64-linux-android": (2, 183),
        "x86_64-linux-android": (2, 62),
    }[target]
    with executable.open("rb") as stream:
        header = stream.read(64)
        if (len(header) < 64 or header[:7] != b"\x7fELF" + bytes((elf_class, 1, 1))
                or struct.unpack_from("<HH", header, 16) != (3, machine)):
            raise RuntimeError("Cross-linked artifact is not the selected Android PIE ELF")
        if elf_class == 2:
            offset = struct.unpack_from("<Q", header, 32)[0]
            size, count = struct.unpack_from("<HH", header, 54)
            if size != 56 or not 0 < count <= 1024 or not 64 <= offset <= 65536:
                raise RuntimeError("Invalid Android ELF program headers")
            stream.seek(offset)
            loads = 0
            for _ in range(count):
                entry = stream.read(size)
                if len(entry) != size:
                    raise RuntimeError("Truncated Android ELF program headers")
                if struct.unpack_from("<I", entry)[0] == 1:
                    loads += 1
                    alignment = struct.unpack_from("<Q", entry, 48)[0]
                    if alignment < 16384 or alignment & (alignment - 1):
                        raise RuntimeError("Android 64-bit LOAD segment lacks 16KB alignment")
            if not loads:
                raise RuntimeError("Android ELF has no LOAD segments")
    dynamic = subprocess.run([str(readelf), "--dynamic", str(executable)],
                             check=True, capture_output=True, text=True).stdout
    needed = sorted(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    system_libraries = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so"}
    if not needed or set(needed) - system_libraries:
        raise RuntimeError(f"Unexpected Android native dynamic dependencies: {needed}")
    with executable.open("rb") as stream:
        sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"target": target, "sha256": sha256, "dt_needed": needed,
            "scope": "real prover harness cross-link and ELF inspection; Android execution not performed"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("This qualification driver requires the existing Linux CI host")
    if (os.environ.get("USE_ZK_MOCK") == "1" or "CARGO_FEATURE_ZK_MOCK" in os.environ
            or "zk_mock" in os.environ.get("RUSTFLAGS", "")
            or "zk_mock" in os.environ.get("CARGO_ENCODED_RUSTFLAGS", "")):
        raise SystemExit("Android cross-link qualification may not use the ZK mock")
    if "ZSTD_SYS_USE_PKG_CONFIG" in os.environ:
        raise SystemExit("Android cross-link qualification may not adopt host zstd")
    ndk = args.ndk_root.resolve(strict=True)
    revisions = [line.split("=", 1)[1].strip()
                 for line in (ndk / "source.properties").read_text().splitlines()
                 if "=" in line and line.split("=", 1)[0].strip() == "Pkg.Revision"]
    if revisions != [NDK_VERSION]:
        raise SystemExit("Android cross-link qualification requires the pinned NDK revision")
    toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64"
    bin_dir, sysroot = toolchain / "bin", toolchain / "sysroot"
    for name in ("clang", "clang++", "llvm-ar", "llvm-ranlib", "llvm-readelf"):
        if not (bin_dir / name).is_file():
            raise SystemExit("Pinned NDK compiler tools are incomplete")
    root = Path(__file__).resolve().parents[1]
    evidence = root / "target/zkp-android-crosslink"
    evidence.mkdir(parents=True, exist_ok=True)
    for target, (llvm, headers) in TARGETS.items():
        target_arg = f"--target={llvm}26"
        env = dict(os.environ)
        for prefix, tool in (("CC", "clang"), ("CXX", "clang++"),
                             ("AR", "llvm-ar"), ("RANLIB", "llvm-ranlib")):
            env[f"{prefix}_{target}"] = str(bin_dir / tool)
        env[f"CFLAGS_{target}"] = target_arg
        env[f"CXXFLAGS_{target}"] = target_arg
        env["CLANG_PATH"] = str(bin_dir / "clang")
        env[f"BINDGEN_EXTRA_CLANG_ARGS_{target.replace('-', '_')}"] = shlex.join([
            target_arg, f"--sysroot={sysroot}", f"-I{sysroot / 'usr/include' / headers}",
        ])
        # Match the consumer's clang linker: clang++ would implicitly add a
        # shared C++ runtime and conceal missing static-runtime link metadata.
        env[f"CARGO_TARGET_{target.replace('-', '_').upper()}_LINKER"] = str(bin_dir / "clang")
        flags = (env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
                 if env.get("CARGO_ENCODED_RUSTFLAGS") else shlex.split(env.get("RUSTFLAGS", "")))
        flags += ["-C", f"link-arg={target_arg}", "-C", f"link-arg=--sysroot={sysroot}"]
        if target != "armv7-linux-androideabi":
            flags += ["-C", "link-arg=-Wl,-z,max-page-size=16384"]
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
        env.update(OPENSSL_NO_VENDOR="0", CARGO_PROFILE_DEV_DEBUG="0",
                   CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0")
        artifact_file = evidence / f"{target}-artifacts.jsonl"
        with artifact_file.open("w", encoding="utf-8") as output:
            subprocess.run([
                "cargo", "test", "--locked", "--offline", "-p", "marty-zkp",
                "--no-default-features", "--features", "prover", "--test", "conformance",
                "--no-run", "--target", target, "--message-format=json",
            ], cwd=root, env=env, stdout=output, check=True)
        artifacts = [json.loads(line) for line in artifact_file.read_text().splitlines()]
        executables = [Path(item["executable"]) for item in artifacts
                       if item.get("reason") == "compiler-artifact" and item.get("executable")
                       and item.get("target", {}).get("name") == "conformance"
                       and Path(item["target"]["src_path"]).resolve()
                       == root / "marty-zkp/tests/conformance.rs"]
        if len(executables) != 1:
            raise RuntimeError("Expected one same-run real prover conformance artifact")
        record = inspect_artifact(executables[0], target, bin_dir / "llvm-readelf")
        (evidence / f"{target}-inspection.json").write_text(json.dumps(record) + "\n")
        print(json.dumps(record, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
