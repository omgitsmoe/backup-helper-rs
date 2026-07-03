#!/usr/bin/env python3
"""Compare outputs of multiple checksum_helper implementations.

Usage:
  ./compare_impls.py <test-dir> [--impl python rust go zig] [-c COMMAND ...]

Commands (default: all):
  build         Build most-current checksum file
  incremental   Generate incremental checksums
  fill          Generate missing checksums
  missing       Check for files without checksums
  verify        Verify checksums in a directory

Examples:
  ./compare_impls.py /tmp/testdir
  ./compare_impls.py /tmp/testdir --impl python rust -c build missing
  ./compare_impls.py /tmp/testdir --impl go zig --prebuilt
"""

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── text parsing helpers ──

RE_ANSI = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
RE_CARRIAGE_RET = re.compile(r'.*\r')
RE_LOG_PREFIX = re.compile(r'^\d{1,2}:\d{2}:\d{2}\s+-\s+\w+\s+-\s+')
RE_LOG_PREFIX_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

def strip_progress(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = RE_ANSI.sub('', line)
        line = RE_CARRIAGE_RET.sub('', line)
        line = RE_LOG_PREFIX.sub('', line)
        line = RE_LOG_PREFIX_TS.sub('', line)
        line = line.rstrip()
        if line:
            lines.append(line)
    return '\n'.join(lines)


# ── format parsers (extract (relpath, hash_hex) from checksum files) ──

def parse_v1_cshd(content: str) -> list[tuple[str, str]]:
    """Parse # version 1 .cshd:  mtime,size,type,hexhash  relpath"""
    result = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        space_idx = line.find(' ')
        if space_idx == -1:
            continue
        hash_part = line[:space_idx]
        relpath = line[space_idx + 1:].strip()
        if not relpath:
            continue
        last_comma = hash_part.rfind(',')
        if last_comma == -1:
            continue
        hexhash = hash_part[last_comma + 1:].strip()
        if not hexhash:
            continue
        result.append((relpath, hexhash))
    return result


def parse_py_cshd(content: str) -> list[tuple[str, str]]:
    """Parse Python .cshd:  mtime,type,hexhash  relpath  (no size, no header)"""
    result = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        space_idx = line.find(' ')
        if space_idx == -1:
            continue
        hash_part = line[:space_idx]
        relpath = line[space_idx + 1:].strip()
        if not relpath:
            continue
        last_comma = hash_part.rfind(',')
        if last_comma == -1:
            continue
        hexhash = hash_part[last_comma + 1:].strip()
        if not hexhash:
            continue
        result.append((relpath, hexhash))
    return result


def parse_std_hash(content: str) -> list[tuple[str, str]]:
    """Parse standard format:  hexhash  [ *]relpath  or  hexhash   relpath"""
    result = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^([0-9a-fA-F]+)\s+[\*\s](.+)$', line)
        if m:
            hexhash, relpath = m.group(1), m.group(2)
            result.append((relpath.strip(), hexhash))
    return result


def detect_format(content: str) -> str:
    if content.startswith('# version 1\n'):
        return 'v1_cshd'
    first = content.splitlines()[0] if content.splitlines() else ''
    if re.match(r'^[0-9.]*,', first) or first.startswith(','):
        return 'py_cshd'
    return 'std_hash'


PARSERS = {
    'v1_cshd': parse_v1_cshd,
    'py_cshd': parse_py_cshd,
    'std_hash': parse_std_hash,
}


# ── console output parsers ──

def parse_missing_python(stdout: str) -> list[tuple[str, str]]:
    """Parse Python check-missing output into (type, path) pairs."""
    items = []
    capturing = False
    for line in stdout.splitlines():
        line = line.strip()
        if 'Directories (D' in line and 'files (F)' in line:
            capturing = True
            continue
        if capturing:
            m = re.match(r'^(D|F)\s+(.+)$', line)
            if m:
                items.append((m.group(1), m.group(2).strip()))
    return items


def parse_missing_rustlike(stdout: str) -> list[tuple[str, str]]:
    """Parse Rust/Go/Zig missing output into (type, path) pairs."""
    items = []
    section = None
    ansi_re = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    for line in stdout.splitlines():
        stripped = ansi_re.sub('', line).strip()
        if not stripped:
            continue
        low = stripped.lower()
        if 'director' in low and 'without' in low:
            section = 'D'
            continue
        if 'files' in low and ('without' in low or 'missing' in low):
            section = 'F'
            continue
        if 'missing' in low and 'file' in low:
            section = 'F'
            continue
        if section:
            if stripped.startswith('\t'):
                path = stripped.strip().strip('"')
                if path:
                    items.append((section, path))
                    continue
            if stripped.startswith('"') and stripped.endswith('"'):
                path = stripped.strip('"')
                items.append((section, path))
                continue
            if not stripped.startswith('"') and not stripped.startswith('\t'):
                if any(kw in low for kw in ('success', 'fail', 'error', 'all file',
                                            'have checksum', 'no issues')):
                    continue
                items.append((section, stripped))
                continue
    return items


PARSE_MISSING = {
    'python': parse_missing_python,
    'rust': parse_missing_rustlike,
    'go': parse_missing_rustlike,
    'zig': parse_missing_rustlike,
}


def parse_verify_python(stdout: str) -> dict:
    """Parse Python verify output into structured data."""
    in_summary = False
    in_missing_section = False
    in_failed_section = False
    result = {
        'total': None, 'matches': None, 'failed': None, 'missing': None,
        'missing_files': [], 'failed_files': [],
    }
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped == 'SUMMARY:':
            in_summary = True
            continue
        if 'NO MISSING FILES!' in stripped:
            in_missing_section = False
            result['missing_files'] = []
            continue
        if 'NO FAILED CHECKSUMS!' in stripped:
            in_failed_section = False
            result['failed_files'] = []
            continue
        if in_summary:
            m = re.match(r'TOTAL FILES:\s+(\d+)', stripped)
            if m: result['total'] = int(m.group(1))
            m = re.match(r'MATCHES:\s+(\d+)', stripped)
            if m: result['matches'] = int(m.group(1))
            m = re.match(r'FAILED CHECKSUMS:\s+(\d+)', stripped)
            if m: result['failed'] = int(m.group(1))
            m = re.match(r'MISSING:\s+(\d+)', stripped)
            if m: result['missing'] = int(m.group(1))
        if 'MISSING FILES:' in stripped:
            in_missing_section = True
            in_failed_section = False
            result['missing_files'] = []
            continue
        if 'FAILED CHECKSUMS:' in stripped:
            in_failed_section = True
            in_missing_section = False
            result['failed_files'] = []
            continue
        if '|--> ' in stripped:
            path = stripped.split('|--> ', 1)[1].strip()
            if 'ROOT FOLDER' in path:
                continue
            if in_failed_section:
                result['failed_files'].append(path)
            elif in_missing_section:
                result['missing_files'].append(path)
    return result


def parse_verify_rustlike(stdout: str) -> dict:
    """Parse Rust/Go/Zig verify output into structured data."""
    result = {
        'total': None, 'ok': None, 'err': None, 'warn': None,
        'missing_files': [], 'mismatch_files': [], 'size_mismatch_files': [],
        'corrupted_files': [], 'outdated_files': [],
    }
    seen_ok = 0
    seen_err = 0
    seen_warn = 0
    for line in stdout.splitlines():
        stripped = line.strip()
        m = re.match(r'Total:\s+(\d+).*OK:\s+(\d+).*ERR:\s+(\d+).*WARN:\s+(\d+)', stripped)
        if m:
            result['total'] = int(m.group(1))
            result['ok'] = int(m.group(2))
            result['err'] = int(m.group(3))
            result['warn'] = int(m.group(4))
        m = re.match(r'\[ERR MISS\s*\].*?"(.+)"', stripped)
        if m:
            result['missing_files'].append(m.group(1))
            seen_err += 1
        m = re.match(r'\[ERR HASH\s*\].*?"(.+)"', stripped)
        if m:
            result['mismatch_files'].append(m.group(1))
            seen_err += 1
        m = re.match(r'\[ERR SIZE\s*\].*?"(.+)"', stripped)
        if m:
            result['size_mismatch_files'].append(m.group(1))
            seen_err += 1
        m = re.match(r'\[ERR CORR\s*\].*?"(.+)"', stripped)
        if m:
            result['corrupted_files'].append(m.group(1))
            seen_err += 1
        m = re.match(r'\[WARN STALE\].*?"(.+)"', stripped)
        if m:
            result['outdated_files'].append(m.group(1))
            seen_warn += 1
        m = re.match(r'\[OK\s+\] (.+)', stripped)
        if m:
            seen_ok += 1
        m = re.match(r'\[FAIL\s+\] (.+)', stripped)
        if m:
            result['mismatch_files'].append(m.group(1))
            seen_err += 1
        m = re.match(r'\[MISSING\s+\] (.+)', stripped)
        if m:
            result['missing_files'].append(m.group(1))
            seen_err += 1
    if result['total'] is None and (seen_ok + seen_err + seen_warn) > 0:
        result['total'] = seen_ok + seen_err + seen_warn
        result['ok'] = seen_ok
        result['err'] = seen_err
        result['warn'] = seen_warn
    return result


PARSE_VERIFY = {
    'python': parse_verify_python,
    'rust': parse_verify_rustlike,
    'go': parse_verify_rustlike,
    'zig': parse_verify_rustlike,
}


# ── implementation definitions ──

COMMANDS = ['build', 'incremental', 'fill', 'missing', 'verify']
FILE_COMMANDS = {'build', 'incremental', 'fill'}
CONSOLE_COMMANDS = {'missing', 'verify'}


@dataclass
class ImplDef:
    key: str
    name: str
    cwd: Path
    run_cmd: list[str]
    timeout: int
    supports: set[str]
    commands: dict

    def build_cmd(self, command: str, root: str) -> list[str]:
        tmpl = self.commands.get(command)
        if tmpl is None:
            return None
        args = [a.replace('{root}', root).replace('{algo}', 'sha512')
                for a in tmpl]
        return self.run_cmd + args

    def run(self, command: str, root: str,
            timeout: int = 0) -> subprocess.CompletedProcess:
        cmd = self.build_cmd(command, root)
        if cmd is None:
            return None
        to = timeout or self.timeout
        try:
            return subprocess.run(
                cmd, cwd=str(self.cwd),
                capture_output=True, text=True,
                timeout=to,
            )
        except subprocess.TimeoutExpired as e:
            return subprocess.CompletedProcess(
                cmd, -1, e.stdout or '', e.stderr or ''
            )
        except FileNotFoundError:
            return None


def make_python(cwd: Path) -> ImplDef:
    return ImplDef(
        key='python', name='Python', cwd=cwd,
        run_cmd=[sys.executable, '-m', 'checksum_helper'],
        timeout=300,
        supports={'build', 'incremental', 'fill', 'missing', 'verify'},
        commands={
            'build':       ['build-most-current', '{root}'],
            'incremental': ['incremental', '{root}', '{algo}'],
            'fill':        ['gen_missing', '{root}', '{algo}'],
            'missing':     ['check-missing', '{root}'],
            'verify':      ['verify', 'all', '{root}'],
        },
    )


def make_rust(cwd: Path) -> ImplDef:
    return ImplDef(
        key='rust', name='Rust', cwd=cwd,
        run_cmd=['cargo', 'run', '--quiet', '--'],
        timeout=600,
        supports={'build', 'incremental', 'fill', 'missing', 'verify'},
        commands={
            'build':       ['build', '{root}', '--hash-block', '.git/**'],
            'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                            '--hash-block', '.git/**'],
            'fill':        ['fill', '{root}', '--all-block', '.git/**'],
            'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
            'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
        },
    )


def make_rust_prebuilt(workspace_root: Path) -> ImplDef | None:
    candidates = [
        workspace_root / 'target' / 'release' / 'checksum_helper_cli',
        workspace_root / 'target' / 'debug' / 'checksum_helper_cli',
    ]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return ImplDef(
                key='rust', name='Rust', cwd=workspace_root,
                run_cmd=[str(p)],
                timeout=120,
                supports={'build', 'incremental', 'fill', 'missing', 'verify'},
                commands={
                    'build':       ['build', '{root}', '--hash-block', '.git/**'],
                    'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                                    '--hash-block', '.git/**'],
                    'fill':        ['fill', '{root}', '--all-block', '.git/**'],
                    'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
                    'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
                },
            )
    return None


def make_go(cwd: Path) -> ImplDef:
    return ImplDef(
        key='go', name='Go', cwd=cwd,
        run_cmd=['go', 'run', './cmd/checksum'],
        timeout=600,
        supports={'build', 'incremental', 'missing'},
        commands={
            'build':       ['build', '{root}', '--hash-block', '.git/**'],
            'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                            '--hash-block', '.git/**'],
            'fill':        ['fill', '{root}', '--all-block', '.git/**'],
            'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
            'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
        },
    )


def make_go_prebuilt(cwd: Path) -> ImplDef | None:
    candidates = [
        cwd / 'checksum',
        Path(os.path.expanduser('~')) / 'go' / 'bin' / 'checksum',
    ]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return ImplDef(
                key='go', name='Go', cwd=cwd,
                run_cmd=[str(p)],
                timeout=120,
                supports={'build', 'incremental', 'missing'},
                commands={
                    'build':       ['build', '{root}', '--hash-block', '.git/**'],
                    'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                                    '--hash-block', '.git/**'],
                    'fill':        ['fill', '{root}', '--all-block', '.git/**'],
                    'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
                    'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
                },
            )
    return None


def make_zig(cwd: Path) -> ImplDef:
    return ImplDef(
        key='zig', name='Zig', cwd=cwd,
        run_cmd=['zig', 'build', 'run', '--'],
        timeout=600,
        supports={'build', 'incremental', 'fill', 'missing', 'verify'},
        commands={
            'build':       ['build', '{root}', '--hash-block', '.git/**'],
            'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                            '--hash-block', '.git/**'],
            'fill':        ['fill', '{root}', '--all-block', '.git/**'],
            'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
            'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
        },
    )


def make_zig_prebuilt(cwd: Path) -> ImplDef | None:
    candidates = [
        cwd / 'zig-out' / 'bin' / 'backup_helper_zig',
    ]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return ImplDef(
                key='zig', name='Zig', cwd=cwd,
                run_cmd=[str(p)],
                timeout=120,
                supports={'build', 'incremental', 'fill', 'missing', 'verify'},
                commands={
                    'build':       ['build', '{root}', '--hash-block', '.git/**'],
                    'incremental': ['incremental', '{root}', '--all-block', '.git/**',
                                    '--hash-block', '.git/**'],
                    'fill':        ['fill', '{root}', '--all-block', '.git/**'],
                    'missing':     ['missing', '{root}', '--hash-block', '.git/**'],
                    'verify':      ['verify', 'root', '{root}', '--hash-block', '.git/**'],
                },
            )
    return None


# ── file detection ──

def find_new_files(before: set[str], after: set[str], root: str) -> list[str]:
    new = after - before
    return sorted(str(p) for p in new)


def scan_cshd_files(root: str) -> set[str]:
    """Return set of absolute paths to .cshd/.sha512/etc files (root only, non-recursive)."""
    files = set()
    for entry in os.listdir(root):
        fpath = os.path.join(root, entry)
        if os.path.isfile(fpath):
            ext = os.path.splitext(entry)[1].lower()
            if ext in HASH_EXTS:
                files.add(os.path.abspath(fpath))
    return files


def remove_generated_files(root: str, keep: set[str]):
    """Remove generated hash files in root, keeping originals in `keep`."""
    for entry in list(os.listdir(root)):
        fpath = os.path.join(root, entry)
        if os.path.isfile(fpath):
            ext = os.path.splitext(entry)[1].lower()
            if ext in HASH_EXTS and os.path.abspath(fpath) not in keep:
                try:
                    os.remove(fpath)
                except OSError:
                    pass


HASH_EXTS = frozenset({
    '.cshd', '.sha512', '.sha256', '.md5', '.sha1',
    '.sha384', '.sha224', '.sha3_224', '.sha3_256',
    '.sha3_384', '.sha3_512',
})


def find_output_file(stdout: str, root: str) -> Optional[str]:
    """Try to find output file path from stdout (Rust: 'Wrote collection at: ...')."""
    for line in stdout.splitlines():
        line = line.strip()
        m = re.search(r'Wrote (collection|file) at:?\s*["\']?([^"\'\]>]+)', line)
        if m:
            path = m.group(2).strip().rstrip('"').rstrip("'")
            path = path.strip('"').strip("'")
            if os.path.exists(path):
                return os.path.abspath(path)
    return None


# ── output collection ──

@dataclass
class CmdResult:
    impl_key: str
    command: str
    stdout: str
    stderr: str
    returncode: int = 0
    output_file: Optional[str] = None
    file_entries: list[tuple[str, str]] = field(default_factory=list)
    parsed_data: Optional[dict] = None

    @property
    def console_text(self) -> str:
        return strip_progress(self.stdout + '\n' + self.stderr)


# ── diff helpers ──

def make_diff(a_label: str, b_label: str, a_lines: list[str], b_lines: list[str]) -> str:
    diff = difflib.unified_diff(
        a_lines, b_lines,
        fromfile=a_label, tofile=b_label,
        lineterm='',
    )
    return '\n'.join(diff)


GIT_FILTER = lambda p: not p.startswith('.git/')


def filter_git_entries(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(p, h) for p, h in entries if GIT_FILTER(p)]


def filter_git_missing(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(t, p) for t, p in items if GIT_FILTER(p)]


def format_entries(entries: list[tuple[str, str]]) -> list[str]:
    s = sorted(f'{h}  {p}' for p, h in filter_git_entries(entries))
    return s


def format_missing_data(items: list[tuple[str, str]]) -> list[str]:
    return sorted(f'{t}  {p}' for t, p in filter_git_missing(items))


def format_verify_data(data: dict) -> list[str]:
    lines = []
    lines.append(f"total={data.get('total')}  ok={data.get('ok')}  err={data.get('err')}  warn={data.get('warn')}")
    for key, label in [('missing_files', 'MISS'), ('mismatch_files', 'HASH'),
                        ('size_mismatch_files', 'SIZE'), ('corrupted_files', 'CORR'),
                        ('outdated_files', 'STALE')]:
        for p in data.get(key, []):
            if GIT_FILTER(p):
                lines.append(f'[{label}] {p}')
    if data.get('matches') is not None:
        lines = [
            f"total={data.get('total')}  matches={data.get('matches')}  "
            f"failed={data.get('failed')}  missing={data.get('missing')}"
        ]
        for p in data.get('missing_files', []):
            if GIT_FILTER(p):
                lines.append(f'[MISS] {p}')
        for p in data.get('failed_files', []):
            if GIT_FILTER(p):
                lines.append(f'[FAIL] {p}')
    return lines


# ── main ──

def auto_detect_impls(include_keys: list[str] | None = None,
                      prebuilt: bool = False) -> list[ImplDef]:
    script_dir = Path(__file__).resolve().parent
    impls_dir = script_dir.parent

    factories = []

    py_path = impls_dir / 'checksum_helper'
    if py_path.is_dir():
        factories.append(('python', lambda: make_python(py_path)))

    rust_ws = impls_dir / 'backup-helper-rs'
    rust_path = rust_ws / 'checksum_helper_cli'
    if rust_path.is_dir():
        if prebuilt:
            factories.append(('rust', lambda: make_rust_prebuilt(rust_ws)))
        if not prebuilt:
            factories.append(('rust', lambda: make_rust(rust_path)))

    go_path = impls_dir / 'backup-helper-go'
    go_exe = shutil.which('go')
    if go_path.is_dir() and (prebuilt or go_exe):
        if prebuilt:
            factories.append(('go', lambda: make_go_prebuilt(go_path)))
        if not prebuilt:
            factories.append(('go', lambda: make_go(go_path)))

    zig_path = impls_dir / 'backup-helper-zig'
    zig_exe = shutil.which('zig')
    if zig_path.is_dir() and (prebuilt or zig_exe):
        if prebuilt:
            factories.append(('zig', lambda: make_zig_prebuilt(zig_path)))
        if not prebuilt:
            factories.append(('zig', lambda: make_zig(zig_path)))

    result = []
    for key, factory in factories:
        if include_keys and key not in include_keys:
            continue
        impl = factory()
        if impl is not None:
            if impl.key == 'python':
                try:
                    subprocess.run(
                        [sys.executable, '-c', 'import checksum_helper'],
                        capture_output=True, timeout=10,
                        cwd=str(impl.cwd),
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            if impl.key in ('rust', 'go', 'zig') and not prebuilt:
                pass
            result.append(impl)
    return result


def run_command(impl: ImplDef, command: str, root: str) -> CmdResult:
    """Run a single command for a single implementation."""
    result = CmdResult(impl_key=impl.key, command=command, stdout='', stderr='')

    before = scan_cshd_files(root) if command in FILE_COMMANDS else set()

    proc = impl.run(command, root)
    if proc is None:
        result.stderr = f'[SKIP] command {command!r} not supported by {impl.name}'
        return result
    if proc.returncode == -1:
        result.stderr = f'[SKIP] {impl.name} timed out or failed to start'
        return result

    result.stdout = proc.stdout
    result.stderr = proc.stderr
    result.returncode = proc.returncode

    if command in FILE_COMMANDS:
        fpath = find_output_file(proc.stdout, root)
        if not fpath:
            after = scan_cshd_files(root)
            new = find_new_files(before, after, root)
            if new:
                fpath = new[0]
        if fpath:
            result.output_file = fpath

        if result.output_file:
            try:
                with open(result.output_file) as f:
                    content = f.read()
                fmt = detect_format(content)
                parser = PARSERS.get(fmt)
                if parser:
                    result.file_entries = parser(content)
            except (OSError, UnicodeDecodeError) as e:
                result.stderr += f'\n[ERROR] Failed to read output file: {e}'

    if command == 'missing':
        parser = PARSE_MISSING.get(impl.key)
        if parser:
            result.parsed_data = parser(result.stdout + '\n' + result.stderr)
    elif command == 'verify':
        parser = PARSE_VERIFY.get(impl.key)
        if parser:
            result.parsed_data = parser(result.stdout + '\n' + result.stderr)

    return result


def compare_results(results: list[CmdResult], command: str):
    """Compare results across implementations for a single command."""
    if len(results) < 2:
        print(f'  [SKIP] Need at least 2 impls to compare {command!r}')
        return

    print(f'\n{"=" * 60}')
    print(f'  {command}')
    print(f'{"=" * 60}')

    for r in results:
        print(f'  [{r.impl_key}] ', end='')
        if r.output_file:
            entries_count = len(r.file_entries)
            print(f'output: {r.output_file}  ({entries_count} entries)')
        elif r.parsed_data:
            if command == 'missing':
                items = r.parsed_data
                print(f'missing: {len(items)} items')
            elif command == 'verify':
                print(f'verify result')
        else:
            print(f'no output captured')

    if command in FILE_COMMANDS:
        results_with_files = [r for r in results if r.file_entries]
        if len(results_with_files) >= 2:
            for i in range(len(results_with_files)):
                for j in range(i + 1, len(results_with_files)):
                    a, b = results_with_files[i], results_with_files[j]
                    a_lines = format_entries(a.file_entries)
                    b_lines = format_entries(b.file_entries)
                    diff = make_diff(f'{a.impl_key}', f'{b.impl_key}', a_lines, b_lines)
                    if diff:
                        print(f'\n  --- diff {a.impl_key} vs {b.impl_key} ---')
                        for dline in diff.splitlines():
                            print(f'  {dline}')
                    else:
                        print(f'\n  --- {a.impl_key} vs {b.impl_key}: IDENTICAL ---')

    if command == 'missing':
        results_with_data = [r for r in results if r.parsed_data is not None]
        if len(results_with_data) >= 2:
            print(f'\n  --- missing data comparison ---')
            for r in results_with_data:
                filtered = filter_git_missing(r.parsed_data)
                print(f'  [{r.impl_key}] {len(filtered)} items:')
                for t, p in sorted(filtered):
                    print(f'    {t}  {p}')
            for i in range(len(results_with_data)):
                for j in range(i + 1, len(results_with_data)):
                    a, b = results_with_data[i], results_with_data[j]
                    a_lines = format_missing_data(a.parsed_data)
                    b_lines = format_missing_data(b.parsed_data)
                    diff = make_diff(f'{a.impl_key}', f'{b.impl_key}', a_lines, b_lines)
                    if diff:
                        print(f'\n  --- diff {a.impl_key} vs {b.impl_key} ---')
                        for dline in diff.splitlines():
                            print(f'  {dline}')
                    else:
                        print(f'  --- {a.impl_key} vs {b.impl_key}: IDENTICAL ---')
        else:
            print(f'  [WARN] No structured missing data to compare')

    elif command == 'verify':
        results_with_data = [r for r in results if r.parsed_data]
        if len(results_with_data) >= 2:
            print(f'\n  --- verify data comparison ---')
            for r in results_with_data:
                lines = format_verify_data(r.parsed_data)
                print(f'  [{r.impl_key}]')
                for ln in lines:
                    print(f'    {ln}')
            for i in range(len(results_with_data)):
                for j in range(i + 1, len(results_with_data)):
                    a, b = results_with_data[i], results_with_data[j]
                    a_lines = format_verify_data(a.parsed_data)
                    b_lines = format_verify_data(b.parsed_data)
                    diff = make_diff(f'{a.impl_key}', f'{b.impl_key}', a_lines, b_lines)
                    if diff:
                        print(f'\n  --- diff {a.impl_key} vs {b.impl_key} ---')
                        for dline in diff.splitlines():
                            print(f'  {dline}')
                    else:
                        print(f'  --- {a.impl_key} vs {b.impl_key}: IDENTICAL ---')
        else:
            print(f'  [WARN] No structured verify data to compare')


def verify_init_files(root: str) -> bool:
    """Check if the test directory has checksum files for the build/fill/incremental commands."""
    files = scan_cshd_files(root)
    hash_files = [f for f in files if os.path.isfile(f)]
    if not hash_files:
        print(f'  [WARN] No checksum files found in {root!r}')
        print(f'         build/fill/incremental commands need existing .cshd/.sha512 files')
        print(f'         missing/verify may still work')
        return False
    return True


def main():
    script_dir = Path(__file__).resolve().parent
    parent = script_dir.parent

    parser = argparse.ArgumentParser(
        description='Compare outputs of multiple checksum_helper implementations.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('test_dir', type=str,
                        help='Test directory containing files to checksum')
    parser.add_argument('--impl', nargs='+',
                        choices=['python', 'rust', 'go', 'zig'],
                        help='Implementations to compare (default: all available)')
    parser.add_argument('--prebuilt', action='store_true',
                        help='Use prebuilt binaries instead of cargo/go/zig run')
    parser.add_argument('-c', '--command', nargs='+',
                        choices=COMMANDS + ['all'],
                        default=['all'],
                        help='Commands to run (default: all)')

    args = parser.parse_args()
    root = os.path.abspath(args.test_dir)
    if not os.path.isdir(root):
        print(f'error: {root!r} is not a directory')
        sys.exit(1)

    impls = auto_detect_impls(
        include_keys=args.impl,
        prebuilt=args.prebuilt,
    )
    if not impls:
        print('error: no implementations found')
        sys.exit(1)

    print(f'Found implementations: {", ".join(i.key for i in impls)}')
    hash_files_exist = verify_init_files(root)

    orig_hash_files = scan_cshd_files(root)

    commands = set(args.command)
    if 'all' in commands:
        commands = set(COMMANDS)

    for cmd in COMMANDS:
        if cmd not in commands:
            continue

        supported = [i for i in impls if cmd in i.supports]
        if not supported:
            print(f'\n  [SKIP] {cmd!r} not supported by any impl')
            continue

        if cmd in FILE_COMMANDS and not hash_files_exist:
            print(f'\n  [SKIP] {cmd!r} requires existing checksum files')
            continue

        results = []
        for impl in supported:
            remove_generated_files(root, orig_hash_files)

            result = run_command(impl, cmd, root)
            results.append(result)

            status = 'OK'
            if result.stderr and '[SKIP]' in result.stderr:
                status = 'SKIP'
            elif result.stderr and '[ERROR]' in result.stderr:
                status = 'ERR'
            elif result.returncode != 0 and result.command != 'missing':
                status = 'ERR'

            print(f'  [{result.impl_key}] {cmd}: {status}',
                  end='', flush=True)
            if result.output_file:
                print(f'  ({len(result.file_entries)} entries)')
            elif result.parsed_data and cmd == 'missing':
                print(f'  ({len(result.parsed_data)} items)')
            else:
                print()

        compare_results(results, cmd)


if __name__ == '__main__':
    main()
