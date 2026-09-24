#!/usr/bin/env python3
"""Restore filesystem metadata on files copied by backup-helper.

The KDL input is intentionally parsed line by line. Each ``target`` belongs to
the most recently seen ``source``; unrelated KDL nodes are ignored.

Usage:
  python3 scripts/copy_metadata.py backup_helper/foo.kdl
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import sys
from pathlib import Path


_QUOTED_STRING = r'"(?:\\.|[^"\\])*"'
_SOURCE_TARGET_NODE = re.compile(
    rf'^\s*(?P<node>source|target)\s+(?P<path>{_QUOTED_STRING})'
)
_STRING_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "s": " ",
    "t": "\t",
}


class ConfigError(ValueError):
    """Raised when the source/target declarations cannot be parsed."""


class MetadataCopyError(RuntimeError):
    """Raised when source and target entries cannot be handled safely."""


def _decode_quoted_string(value: str, line_number: int) -> str:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ConfigError(f"line {line_number}: expected a quoted path")

    decoded: list[str] = []
    index = 1
    end = len(value) - 1
    while index < end:
        character = value[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue

        index += 1
        if index >= end:
            raise ConfigError(f"line {line_number}: path ends with an incomplete escape")

        escaped = value[index]
        simple_escape = _STRING_ESCAPES.get(escaped)
        if simple_escape is not None:
            decoded.append(simple_escape)
            index += 1
            continue

        if escaped == "u":
            index += 1
            if index >= end or value[index] != "{":
                raise ConfigError(f"line {line_number}: invalid Unicode escape in path")

            closing_brace = value.find("}", index + 1)
            if closing_brace == -1 or closing_brace >= end:
                raise ConfigError(f"line {line_number}: unterminated Unicode escape in path")

            codepoints = value[index + 1 : closing_brace]
            if not codepoints or any(
                part == "" or any(digit not in "0123456789abcdefABCDEF" for digit in part)
                for part in codepoints.split(",")
            ):
                raise ConfigError(f"line {line_number}: invalid Unicode escape in path")

            try:
                decoded.append("".join(chr(int(part, 16)) for part in codepoints.split(",")))
            except ValueError as error:
                raise ConfigError(
                    f"line {line_number}: invalid Unicode escape in path"
                ) from error
            index = closing_brace + 1
            continue

        raise ConfigError(f"line {line_number}: unsupported path escape \\{escaped}")

    return "".join(decoded)


def _parse_absolute_path(value: str, line_number: int) -> Path:
    if not value:
        raise ConfigError(f"line {line_number}: path must not be empty")

    path = Path(value)
    if not path.is_absolute():
        raise ConfigError(f"line {line_number}: path must be absolute: {value!r}")
    return path


def parse_source_targets(config_path: Path) -> list[tuple[Path, tuple[Path, ...]]]:
    """Return each unique source with its unique, associated target paths."""
    targets_by_source: dict[Path, list[Path]] = {}
    seen_targets: dict[Path, set[Path]] = {}
    current_source: Path | None = None

    with config_path.open("r", encoding="utf-8") as config_file:
        for line_number, line in enumerate(config_file, start=1):
            match = _SOURCE_TARGET_NODE.match(line)
            if match is None:
                continue

            node_name = match.group("node")
            path = _parse_absolute_path(
                _decode_quoted_string(match.group("path"), line_number), line_number
            )

            if node_name == "source":
                current_source = path
                targets_by_source.setdefault(path, [])
                seen_targets.setdefault(path, set())
            else:
                if current_source is None:
                    raise ConfigError(
                        f"line {line_number}: target appears before any source declaration"
                    )
                if path not in seen_targets[current_source]:
                    seen_targets[current_source].add(path)
                    targets_by_source[current_source].append(path)

    source_targets = [
        (source, tuple(targets_by_source[source]))
        for source, targets in targets_by_source.items()
        if targets
    ]
    if not source_targets:
        raise ConfigError(f"no source/target pairs found in {config_path}")
    return source_targets


def _raise_walk_error(error: OSError) -> None:
    raise error


def _is_regular_source_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError as error:
        raise MetadataCopyError(f"cannot stat source file {path}: {error}") from error


def _target_file_exists(path: Path) -> bool:
    try:
        target_stat = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise MetadataCopyError(f"cannot stat target path {path}: {error}") from error

    if not stat.S_ISREG(target_stat.st_mode):
        raise MetadataCopyError(f"target path exists but is not a regular file: {path}")
    return True


def copy_metadata(
    source_targets: list[tuple[Path, tuple[Path, ...]]],
    *,
    dry_run: bool = False,
) -> tuple[int, int]:
    """Copy metadata for existing target files and return updated/missing counts."""
    updated = 0
    missing = 0

    for source, targets in source_targets:
        print(f"Processing source {source} with targets {targets}")
        if not source.is_dir():
            raise MetadataCopyError(f"source is not a directory: {source}")

        for root, _, filenames in os.walk(
            source, topdown=True, onerror=_raise_walk_error, followlinks=False
        ):
            root_path = Path(root)
            for filename in filenames:
                source_file = root_path / filename
                if not _is_regular_source_file(source_file):
                    continue

                relative_path = source_file.relative_to(source)
                for target in targets:
                    target_file = target / relative_path
                    if not _target_file_exists(target_file):
                        missing += 1
                        continue

                    if not dry_run:
                        try:
                            shutil.copystat(
                                source_file, target_file, follow_symlinks=True
                            )
                        except OSError as error:
                            raise MetadataCopyError(
                                f"failed to copy metadata from "
                                f"{source_file} to {target_file}: {error}"
                            ) from error
                    # print(f"Update file metadata\n\t{source_file} -> {target_file}")
                    updated += 1

    return updated, missing


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy permissions and timestamps from backup-helper source files "
            "to existing target files described by a KDL configuration."
        )
    )
    parser.add_argument("config", type=Path, help="path to the backup-helper KDL configuration")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report matching target files without changing their metadata",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        source_targets = parse_source_targets(args.config)
        updated, missing = copy_metadata(source_targets, dry_run=args.dry_run)
    except (ConfigError, MetadataCopyError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    action = "Would update" if args.dry_run else "Updated"
    print(
        f"{action} metadata for {updated} existing file(s); "
        f"skipped {missing} missing target file(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
