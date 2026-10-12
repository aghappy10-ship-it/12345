"""Build and inspect a local-only, menu-only AArch64 preload. Never deploys.

Uses exact stock Bionic libraries as linker inputs without copying system images.
See THIRD_PARTY_NOTICES.txt for the reference approach attribution.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile

try:
    from .output_guard import guard_output, output_directory, write_output
    from .qt_unit import GUI_SHA256, require, read_main_screen
    from .build_unit import DEVICE_URL, validate_preservation
except ImportError:
    from output_guard import guard_output, output_directory, write_output
    from qt_unit import GUI_SHA256, require, read_main_screen
    from build_unit import DEVICE_URL, validate_preservation

PROJECT = Path(__file__).resolve().parents[1]
STOCK_ROOT = PROJECT.parent / 'x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root'
ZIG = PROJECT.parent / 'x2d2/work/reverse/vendor/tools/zig-x86_64-windows-0.15.2/zig.exe'
ZIG_HASH = 'd408dd38eed3e5204af841bcebf70502a4dbbb8399a3a3262be55059370bc018'
LIB_HASHES = {
    'libc.so': '1af0737faf17f3589eb72e03efd31dc1316560b6c14b4c4e2f503d24287d13e4',
    'libdl.so': '0d40d030eda384fe7d99441954f82670333cb56eb55cb968098ed589a276b53f',
}
SYMBOL_PREFIX = '_ZN21QmlCacheGeneratedCode39_qt_qml_app_qml_mainmenu_MainScreen_qml'
ALLOWED_IMPORTS = {'dl_iterate_phdr', 'open', 'close', 'write', 'lseek', 'memcmp',
                   'strcmp', 'getenv', 'getpid', 'readlink', '__errno', '_exit'}
FINAL_NAMES = ('stock-unit.bin', 'extended-unit.bin', 'baseline.h', 'units.S',
               'menu_preload.c', 'libx2dii_menu.so', 'native-build.json')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_offset(elf: ELFFile, address: int, size: int) -> int:
    candidates = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                  and s['p_vaddr'] <= address
                  and address + size <= s['p_vaddr'] + s['p_filesz']]
    require(size >= 0 and len(candidates) == 1, 'ELF address must have one file-backed load segment')
    segment = candidates[0]
    return address - segment['p_vaddr'] + segment['p_offset']


def inspect_baseline(raw: bytes) -> dict:
    require(sha(raw) == GUI_SHA256, 'exact GUI hash required')
    elf = ELFFile(io.BytesIO(raw))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64'
            and elf['e_type'] == 'ET_DYN', 'baseline ELF identity')
    symbols = elf.get_section_by_name('.symtab')
    require(symbols is not None, 'baseline symbols missing')

    def symbol(suffix):
        found = symbols.get_symbol_by_name(SYMBOL_PREFIX + suffix)
        require(found is not None and len(found) == 1, 'unique MainScreen symbol required')
        return found[0]

    unit, cache, aot = (symbol(s) for s in ('7qmlDataE', 'L4unitE', '17aotBuiltFunctionsE'))
    require(unit['st_size'] == 14896 and cache['st_size'] == 24 and aot['st_size'] == 1008,
            'baseline symbol sizes changed')
    relocations = {}
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_RELA':
            for relocation in section.iter_relocations():
                offset = relocation['r_offset']
                if (cache['st_value'] <= offset < cache['st_value'] + cache['st_size'] or
                        aot['st_value'] <= offset < aot['st_value'] + aot['st_size']):
                    require(offset not in relocations and relocation['r_info_type'] == 1027
                            and relocation['r_info_sym'] == 0, 'unexpected/duplicate main cache relocation')
                    relocations[offset] = relocation['r_addend']
    cv, uv, av = cache['st_value'], unit['st_value'], aot['st_value']
    require(relocations.get(cv) == uv and relocations.get(cv + 8) == av
            and cv + 16 not in relocations, 'cached unit relocation layout')
    require(struct.unpack_from('<3Q', raw, file_offset(elf, cv, 24)) == (uv, av, 0),
            'cached unit file contents differ from pointer relocations')
    aot_raw = raw[file_offset(elf, av, aot['st_size']):][:aot['st_size']]
    words = []
    for index, (value,) in enumerate(struct.iter_unpack('<Q', aot_raw)):
        relative = av + index * 8 in relocations
        if relative:
            require(value == relocations[av + index * 8], 'AOT relocation addend mismatch')
            file_offset(elf, value, 4)
        words.append({'value': value, 'relative': relative})
    note = elf.get_section_by_name('.note.gnu.build-id')
    require(note is not None and note['sh_size'] == 32, 'baseline build identity missing')
    file_offset(elf, note['sh_addr'], note['sh_size'])
    fields = ['p_type', 'p_flags', 'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz', 'p_memsz', 'p_align']
    loads = [[1 if name == 'p_type' else segment[name] for name in fields]
             for segment in elf.iter_segments() if segment['p_type'] == 'PT_LOAD']
    return {'guiSha256': GUI_SHA256, 'unitVa': uv, 'unitBytes': unit['st_size'],
            'cacheVa': cv, 'cacheFileOffset': file_offset(elf, cv, 24), 'aotVa': av,
            'aotWords': words, 'buildNoteVa': note['sh_addr'], 'buildNoteHex': note.data().hex(),
            'loads': loads, 'cacheRelocationsVerified': True}


def baseline_header(baseline: dict, size: int) -> str:
    lines = ['/* Generated from hash-verified X2D II baseline. */']
    for name, value in [('UNIT_VA', baseline['unitVa']), ('UNIT_SIZE', baseline['unitBytes']),
                        ('CACHE_VA', baseline['cacheVa']), ('AOT_VA', baseline['aotVa']),
                        ('BUILD_NOTE_VA', baseline['buildNoteVa']), ('EXTENDED_UNIT_SIZE', size),
                        ('LOAD_COUNT', len(baseline['loads'])), ('AOT_WORD_COUNT', len(baseline['aotWords']))]:
        lines.append(f'#define {name} {value}UL')
    lines.append('static const struct phdr expected_loads[] = {')
    lines += ['    {' + ','.join(str(v) + 'ULL' for v in load) + '},' for load in baseline['loads']]
    lines.append('};\nstatic const unsigned char expected_build_note[] = {')
    lines.append(','.join('0x' + format(b, '02x') for b in bytes.fromhex(baseline['buildNoteHex'])) + '};')
    lines.append('static const struct aot_word expected_aot[] = {')
    lines += [f'    {{{word["value"]}ULL, {int(word["relative"])}}},' for word in baseline['aotWords']]
    lines.append('};\n')
    return '\n'.join(lines)


def inspect_library(raw: bytes, exports: set[str]) -> dict:
    elf = ELFFile(io.BytesIO(raw))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64'
            and elf['e_type'] == 'ET_DYN', 'output must be ARM64 LE shared object')
    require(not any((s['p_flags'] & 3) == 3 for s in elf.iter_segments()), 'writable executable segment')
    require(any(s['p_type'] == 'PT_GNU_RELRO' for s in elf.iter_segments()), 'RELRO missing')
    stacks = [s for s in elf.iter_segments() if s['p_type'] == 'PT_GNU_STACK']
    require(len(stacks) == 1 and not stacks[0]['p_flags'] & 1, 'non-executable stack required')
    imports = {s.name for s in elf.get_section_by_name('.dynsym').iter_symbols()
               if s.name and s['st_shndx'] == 'SHN_UNDEF'}
    require(imports <= exports and imports <= ALLOWED_IMPORTS, 'unknown import: ' + repr(imports - (exports & ALLOWED_IMPORTS)))
    needed = []
    for tag in elf.get_section_by_name('.dynamic').iter_tags():
        require(tag.entry.d_tag != 'DT_TEXTREL', 'text relocations forbidden')
        if tag.entry.d_tag == 'DT_NEEDED': needed.append(tag.needed)
    require(set(needed) <= set(LIB_HASHES) and 'libc.so' in needed, 'unexpected library dependencies')
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_RELA':
            for r in section.iter_relocations():
                require(r['r_info_type'] in (257, 1025, 1026, 1027), 'unknown relocation')
                segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                            and s['p_vaddr'] <= r['r_offset']
                            and r['r_offset'] + 8 <= s['p_vaddr'] + s['p_memsz']]
                require(len(segments) == 1 and segments[0]['p_flags'] & 2, 'relocation outside writable load')
    init = elf.get_section_by_name('.init_array')
    require(init is not None and init['sh_size'] == 8, 'exactly one constructor required')
    require(elf.get_section_by_name('.eh_frame') is not None, 'native unwind metadata missing')
    return {'imports': sorted(imports), 'dependencies': needed, 'bytes': len(raw), 'sha256': sha(raw),
            'nonExecutableStack': True, 'noWritableExecutableSegment': True, 'relro': True,
            'unwindPresent': True, 'constructorCount': 1}


def build(root: Path = STOCK_ROOT, zig: Path = ZIG) -> dict:
    output = PROJECT / 'build/native'
    stage_root = PROJECT / 'build/native-staging'

    def preflight():
        # Check every member before any directory/file creation or publication.
        # Rechecking here closes long compiler-time gaps; it is not a lock
        # against a malicious concurrent parent-directory replacement.
        for directory in (output, stage_root):
            guard_output(directory)
            require(not directory.exists() or directory.is_dir(), 'output directory required')
        for name in FINAL_NAMES:
            path = guard_output(output / name)
            require(not path.exists() or path.is_file(), 'output file required: ' + name)

    preflight()
    require(sha(zig.read_bytes()) == ZIG_HASH, 'Zig hash mismatch')
    gui = root / 'bin/camera-gui'
    original = read_main_screen(gui)
    candidate_path = PROJECT / 'build/units/main-screen-bootstrap-device.bin'
    candidate = candidate_path.read_bytes()
    validate_preservation(original, candidate, DEVICE_URL)
    baseline = inspect_baseline(gui.read_bytes())
    libraries, exports = [], set()
    for name, digest in LIB_HASHES.items():
        path = root / 'lib64' / name
        raw = path.read_bytes()
        require(sha(raw) == digest, 'stock library hash mismatch: ' + name)
        library = ELFFile(io.BytesIO(raw))
        exports.update(s.name for s in library.get_section_by_name('.dynsym').iter_symbols()
                       if s['st_shndx'] != 'SHN_UNDEF')
        libraries.append(path)
    assembly = '.section .rodata\n.balign 8\n'
    for label, name in [('stock_unit', 'stock-unit.bin'), ('extended_unit', 'extended-unit.bin')]:
        assembly += f'.global {label}, {label}_end\n.hidden {label}, {label}_end\n{label}:\n.incbin "{name}"\n{label}_end:\n.balign 8\n'
    assembly += '.section .note.GNU-stack,"",%progbits\n'
    source = PROJECT / 'src/menu_preload.c'
    inputs = {'stock-unit.bin': original, 'extended-unit.bin': candidate,
              'baseline.h': baseline_header(baseline, len(candidate)).encode('ascii'),
              'units.S': assembly.encode('utf-8'), 'menu_preload.c': source.read_bytes()}
    # Only small immutable snapshots are staged; stock images and linker
    # libraries stay read-only in their original locations.
    stage = guard_output(Path(tempfile.mkdtemp(prefix='run-', dir=output_directory(stage_root))))
    command = [str(zig.resolve()), 'cc', '-target', 'aarch64-linux-gnu', '-O2', '-g0', '-fPIC', '-shared',
               '-nostdlib', '-ffreestanding', '-fno-builtin', '-ffixed-x18', '-fno-stack-protector',
               '-fasynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror',
               '-Wl,--no-undefined', '-Wl,-z,noexecstack', '-Wl,-z,relro', '-Wl,-z,now',
               '-Wl,--build-id=sha1', '-Wl,-soname,libx2dii_menu.so',
               '-I.', 'menu_preload.c', 'units.S',
               *(str(p.resolve()) for p in libraries), '-o', 'libx2dii_menu.so']
    runs = []
    library_bytes = []
    for number in (1, 2):
        directory = output_directory(stage / ('build-' + str(number)))
        for name, data in inputs.items():
            write_output(directory / name, data)
        local_cache = output_directory(directory / 'zig-local')
        global_cache = output_directory(directory / 'zig-global')
        target = guard_output(directory / 'libx2dii_menu.so', must_be_new=True)
        env = os.environ.copy()
        env.update(ZIG_LOCAL_CACHE_DIR=str(local_cache), ZIG_GLOBAL_CACHE_DIR=str(global_cache))
        # Preserve each run and compiler diagnostics even on failure. Never
        # direct an external compiler at an existing final output or cache.
        command_path = directory / 'command.json'
        write_output(command_path, (json.dumps({'command': command, 'cwd': str(directory),
                     'localCache': str(local_cache), 'globalCache': str(global_cache)}, indent=2) + '\n').encode())
        try:
            result = subprocess.run(command, cwd=directory, env=env, check=True,
                                    timeout=180, capture_output=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            for name, data in (('compiler.stdout', getattr(error, 'stdout', None)),
                               ('compiler.stderr', getattr(error, 'stderr', None))):
                write_output(directory / name, data.encode() if isinstance(data, str) else data or b'')
            write_output(directory / 'failure.json', (json.dumps({'error': type(error).__name__,
                         'returncode': getattr(error, 'returncode', None),
                         'timeout': getattr(error, 'timeout', None)}, indent=2) + '\n').encode())
            raise
        for name, data in (('compiler.stdout', result.stdout), ('compiler.stderr', result.stderr)):
            write_output(directory / name, data or b'')
        guard_output(target)
        for name, data in inputs.items():
            require((directory / name).read_bytes() == data, 'staged input changed: ' + name)
        raw = target.read_bytes()
        checked = inspect_library(raw, exports)
        library_bytes.append(raw)
        runs.append({'directory': str(directory), 'library': checked,
                     'localCache': str(local_cache), 'globalCache': str(global_cache)})
    require(library_bytes[0] == library_bytes[1], 'independent native builds differ')
    # Report source hashes describe the exact snapshots given to both compilers.
    # Detect ordinary input changes while building before publishing any file.
    require(source.read_bytes() == inputs['menu_preload.c'], 'native source changed during build')
    require(candidate_path.read_bytes() == candidate, 'extended unit changed during build')
    require(sha(zig.read_bytes()) == ZIG_HASH, 'Zig changed during build')
    require(sha(gui.read_bytes()) == GUI_SHA256, 'stock GUI changed during build')
    for path in libraries:
        require(sha(path.read_bytes()) == LIB_HASHES[path.name], 'stock linker input changed during build')
    report = {'status': 'LOCAL_COMPONENT_ONLY', 'installable': False, 'cameraValidated': False,
              'baseline': baseline, 'library': runs[0]['library'], 'linkInputHashes': LIB_HASHES,
              'zigSha256': ZIG_HASH, 'command': command, 'builderSha256': sha(Path(__file__).read_bytes()),
              'sourceSha256': sha(inputs['menu_preload.c']), 'headerSha256': sha(inputs['baseline.h']),
              'stockUnitSha256': sha(original), 'extendedUnitSha256': sha(candidate),
              'reproducibility': {'result': 'PASS', 'independentBuilds': 2,
                                  'exactLibraryBytesEqual': True, 'freshCaches': True, 'runs': runs},
              'publication': {'allFinalPathsPreflighted': True, 'reportPublishedLast': True,
                              'atomicPerFileReplacement': True, 'readbackVerified': True,
                              'concurrentParentDirectoryReplacementProtected': False},
              'cameraWrites': 0, 'modifiedRuntimeFields': ['MainScreen.CachedQmlUnit.data'],
              'unverified': ['current device baseline, loader policy and tmpfs marker location',
                             'full native constructor execution', 'real camera QML, keys, capture and rollback']}
    final_data = {**inputs, 'libx2dii_menu.so': library_bytes[0]}
    report['artifactHashes'] = {name: sha(data) for name, data in final_data.items()}
    final_data['native-build.json'] = (json.dumps(report, indent=2) + '\n').encode('utf-8')
    preflight()
    for name in FINAL_NAMES:
        write_output(output / name, final_data[name])
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-root', type=Path, default=STOCK_ROOT)
    parser.add_argument('--zig', type=Path, default=ZIG)
    args = parser.parse_args()
    result = build(args.stock_root, args.zig)
    print(json.dumps({k: result[k] for k in ('status', 'installable', 'library', 'cameraWrites')}, indent=2))
