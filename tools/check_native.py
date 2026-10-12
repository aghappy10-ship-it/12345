"""Execute the actual menu constructor and image callback in ARM64 Unicorn.

libc/loader calls are simulated; no camera or process-memory device is accessed.
Every scenario uses fresh emulator memory. This is not device qualification.
"""
from __future__ import annotations

import gc
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
VENDOR = PROJECT.parent / "x2d2/work/reverse/vendor/python"
sys.path.insert(0, str(VENDOR))

import unicorn
from unicorn import arm64_const
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X18, UC_ARM64_REG_X19, UC_ARM64_REG_X29,
                                 UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC)
import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE

try:
    from .output_guard import write_output
    from .qt_unit import GUI_SHA256, MAIN_SHA256, require, sha256_file
except ImportError:
    from output_guard import write_output
    from qt_unit import GUI_SHA256, MAIN_SHA256, require, sha256_file

GUI = PROJECT.parent / "x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root/bin/camera-gui"
PREFIX = "_ZN21QmlCacheGeneratedCode39_qt_qml_app_qml_mainmenu_MainScreen_qml"
LIB, APP, STUBS, SCRATCH = 0x400000000, 0x100000000, 0x600000000, 0x700000000
MASK = (1 << 64) - 1
NONBLOCK, CREAT, EXCL, TRUNC, NOFOLLOW, CLOEXEC = 2048, 64, 128, 512, 131072, 524288
STATUS_EXISTING_CASES = tuple("status_existing_" + kind for kind in
                              ("regular", "hardlink", "symlink", "fifo", "socket", "directory", "device"))
MARKER_EXISTING_CASES = tuple("marker_existing_" + kind for kind in
                              ("regular", "hardlink", "symlink", "fifo", "socket", "directory", "device"))
STATUS_FAILURE_CASES = ("status_open_fail", "status_write_fail", "status_short_write", "status_close_fail")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pack64(value: int) -> bytes:
    return struct.pack("<Q", value)


class NativeHarness:
    """Inputs verified independently from the builder's recorded validation."""
    def __init__(self):
        native = PROJECT / "build/native"
        self.raw = (native / "libx2dii_menu.so").read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.build_report = json.loads((native / "native-build.json").read_text(encoding="utf-8"))
        require(sha(self.raw) == self.build_report["library"]["sha256"], "stale native library evidence")
        for key, path in (("sourceSha256", PROJECT / "src/menu_preload.c"),
                          ("headerSha256", native / "baseline.h"),
                          ("extendedUnitSha256", PROJECT / "build/units/main-screen-bootstrap-device.bin")):
            require(sha256_file(path) == self.build_report[key], "stale build source/input evidence: " + key)
        require(sha256_file(GUI) == GUI_SHA256, "wrong stock ELF hash")
        with GUI.open("rb") as stream:
            stock = ELFFile(stream)
            symbols = stock.get_section_by_name(".symtab")
            self.addresses = {}
            for label, suffix in (("unit", "7qmlDataE"), ("cache", "L4unitE"), ("aot", "17aotBuiltFunctionsE")):
                matches = symbols.get_symbol_by_name(PREFIX + suffix)
                require(matches is not None and len(matches) == 1, "ambiguous stock symbol")
                self.addresses[label] = (int(matches[0]["st_value"]), int(matches[0]["st_size"]))
            require(tuple(self.addresses[k][1] for k in ("unit", "cache", "aot")) == (14896, 24, 1008),
                    "unexpected stock symbol lengths")
            self.loads = []
            for segment in stock.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    fields = (1, segment["p_flags"], segment["p_offset"], segment["p_vaddr"],
                              segment["p_paddr"], segment["p_filesz"], segment["p_memsz"], segment["p_align"])
                    self.loads.append((fields, segment.data()))
            note = stock.get_section_by_name(".note.gnu.build-id")
            self.note_va, self.note = int(note["sh_addr"]), note.data()
            self.app_relocations = []
            for section in stock.iter_sections():
                if section["sh_type"] != "SHT_RELA":
                    continue
                for rel in section.iter_relocations():
                    if any(start <= rel["r_offset"] < start + size
                           for start, size in (self.addresses["cache"], self.addresses["aot"])):
                        require(rel["r_info_type"] == 1027 and rel["r_info_sym"] == 0, "unknown app relocation")
                        self.app_relocations.append((int(rel["r_offset"]), int(rel["r_addend"])))
        require([list(fields) for fields, _ in self.loads] == self.build_report["baseline"]["loads"],
                "load headers differ from generated input")
        self.symbols = {s.name: (int(s["st_value"]), int(s["st_size"]))
                        for s in self.elf.get_section_by_name(".symtab").iter_symbols() if s.name}
        self.unwind = self.check_code_and_unwind()

    def check_code_and_unwind(self) -> dict:
        require(self.elf["e_machine"] == "EM_AARCH64", "wrong native instruction architecture")
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        decoder.detail = True
        count = 0
        for section in self.elf.iter_sections():
            if not section["sh_flags"] & 4:
                continue
            for instruction in decoder.disasm(section.data(), section["sh_addr"]):
                read, written = instruction.regs_access()
                require(not any(instruction.reg_name(reg) in ("x18", "w18") for reg in read + written),
                        "platform register x18 used")
                count += 1
        require(count > 0, "no executable instructions decoded")
        fdes = []
        for entry in self.elf.get_dwarf_info().EH_CFI_entries():
            if isinstance(entry, FDE):
                rows = entry.get_decoded().table
                require(rows and all("cfa" in row for row in rows), "unusable unwind CFA rows")
                fdes.append((entry["initial_location"], entry["initial_location"] + entry["address_range"], len(rows)))
        # A mapped executable section is not a verified function body. Derive
        # instruction PCs from this ELF's symbols, exact FDEs and complete
        # disassembly; do not truncate at early returns or bridge padding gaps.
        pcs, bodies = set(), []
        functions = {symbol.name: symbol for symbol in self.elf.get_section_by_name(".symtab").iter_symbols()
                     if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_shndx"] != "SHN_UNDEF"}
        names = ("install", "image", "status", "replace_pointer")
        require(set(functions) == set(names), "unverified native function set")
        for name in names:
            symbol = functions[name]
            start, size = int(symbol["st_value"]), int(symbol["st_size"])
            section = self.elf.get_section(symbol["st_shndx"])
            offset = start - int(section["sh_addr"])
            require(section["sh_flags"] & 4 and start % 4 == 0 and size > 0 and size % 4 == 0
                    and 0 <= offset and offset + size <= section["sh_size"], "invalid native body: " + name)
            require(sum(low == start and high == start + size for low, high, _ in fdes) == 1,
                    "non-exact unwind body: " + name)
            instructions = list(decoder.disasm(section.data()[offset:offset + size], start))
            require([instruction.address for instruction in instructions] == list(range(start, start + size, 4))
                    and all(instruction.size == 4 for instruction in instructions), "incomplete native body: " + name)
            body_pcs = {LIB + instruction.address for instruction in instructions}
            require(not pcs.intersection(body_pcs), "overlapping native bodies")
            pcs.update(body_pcs)
            bodies.append({"name": name, "start": start, "end": start + size, "instructions": len(instructions)})

        # Only relocation-bound AArch64 import veneers are executable PLT code.
        # The resolver header and unallocated stub slots are not boundaries.
        plt, relocations = self.elf.get_section_by_name(".plt"), self.elf.get_section_by_name(".rela.plt")
        require(plt is not None and relocations is not None and plt["sh_flags"] & 4, "missing import veneers")
        imports = self.elf.get_section(relocations["sh_link"])
        veneers = []
        for index, relocation in enumerate(relocations.iter_relocations()):
            symbol = imports.get_symbol(relocation["r_info_sym"])
            require(relocation["r_info_type"] == 1026 and relocation["r_addend"] == 0
                    and symbol["st_shndx"] == "SHN_UNDEF", "unverified import relocation")
            offset = 32 + index * 16
            start = int(plt["sh_addr"]) + offset
            instructions = list(decoder.disasm(plt.data()[offset:offset + 16], start))
            require(len(instructions) == 4 and all(instruction.size == 4 and not instruction.writeback
                    and not instruction.update_flags for instruction in instructions)
                    and [instruction.address for instruction in instructions]
                    == list(range(start, start + 16, 4))
                    and [instruction.mnemonic for instruction in instructions] == ["adrp", "ldr", "add", "br"],
                    "unverified import veneer: " + symbol.name)
            page, load, add, branch = (instruction.operands for instruction in instructions)
            reg, imm, mem = capstone.arm64.ARM64_OP_REG, capstone.arm64.ARM64_OP_IMM, capstone.arm64.ARM64_OP_MEM
            require(len(page) == 2 and page[0].type == reg and decoder.reg_name(page[0].reg) == "x16"
                    and page[1].type == imm and len(load) == 2 and load[0].type == reg
                    and decoder.reg_name(load[0].reg) == "x17" and load[1].type == mem
                    and decoder.reg_name(load[1].mem.base) == "x16" and load[1].mem.index == 0
                    and len(add) == 3 and all(op.type == reg and decoder.reg_name(op.reg) == "x16" for op in add[:2])
                    and add[2].type == imm and add[2].imm == load[1].mem.disp
                    and add[2].shift.type == capstone.arm64.ARM64_SFT_INVALID and add[2].shift.value == 0
                    and len(branch) == 1 and branch[0].type == reg and decoder.reg_name(branch[0].reg) == "x17"
                    and page[1].imm + load[1].mem.disp == relocation["r_offset"],
                    "import veneer does not match relocation: " + symbol.name)
            pcs.update(LIB + instruction.address for instruction in instructions)
            veneers.append({"name": symbol.name, "start": start, "end": start + 16})
        require(veneers and plt["sh_size"] == 32 + 16 * len(veneers), "unverified PLT extent")
        self.native_instruction_pcs = frozenset(pcs)
        return {"instructionsDecoded": count, "x18Referenced": False, "fdeCount": len(fdes),
                "coveredFunctions": list(names), "runtimeExceptionUnwindTested": False,
                "executionBodies": bodies, "importVeneers": veneers,
                "verifiedNativeInstructionCount": len(pcs)}

    def run(self, case: str, *, aot_index: int | None = None, pid: int = 3217,
            diagnostic_case: str | None = None) -> dict:
        # Pinned Unicorn 2.0.1 retains Python/native callback cycles. Collect
        # only unreachable engines outside guest callbacks, before the next
        # large mapping and after a completed scenario. An active traceback
        # or other caller-owned engine remains reachable and is not closed.
        gc.collect()
        try:
            return self._run(case, aot_index=aot_index, pid=pid,
                             diagnostic_case=diagnostic_case)
        finally:
            gc.collect()

    def _run(self, case: str, *, aot_index: int | None = None, pid: int = 3217,
             diagnostic_case: str | None = None) -> dict:
        status_case = case if diagnostic_case is None else diagnostic_case
        require(diagnostic_case is None or diagnostic_case in (*STATUS_FAILURE_CASES, *STATUS_EXISTING_CASES),
                "unknown diagnostic fault scenario")
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(LIB, 0x40000)
        app_size = (max(fields[3] + fields[6] for fields, _ in self.loads) + 4095) & ~4095
        u.mem_map(APP, app_size)
        u.mem_map(STUBS, 0x10000)
        u.mem_map(SCRATCH, 0x20000)
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                u.mem_write(LIB + segment["p_vaddr"], segment.data())
        imports = {}
        for section in self.elf.iter_sections():
            if section["sh_type"] != "SHT_RELA":
                continue
            symbols = self.elf.get_section(section["sh_link"])
            for rel in section.iter_relocations():
                kind = rel["r_info_type"]
                if kind == 1027:
                    value = LIB + rel["r_addend"]
                else:
                    symbol = symbols.get_symbol(rel["r_info_sym"])
                    if symbol["st_shndx"] == "SHN_UNDEF":
                        require(kind in (1025, 1026), "unsupported imported relocation")
                        value = STUBS + 0x100 + len(imports) * 16
                        imports[value] = symbol.name
                    else:
                        require(kind in (257, 1025, 1026), "unsupported defined relocation")
                        value = LIB + symbol["st_value"] + rel["r_addend"]
                u.mem_write(LIB + rel["r_offset"], pack64(value))
        for fields, data in self.loads:
            u.mem_write(APP + fields[3], data)
        for offset, addend in self.app_relocations:
            u.mem_write(APP + offset, pack64(APP + addend))
        unit = APP + self.addresses["unit"][0]
        cache = APP + self.addresses["cache"][0]
        aot = APP + self.addresses["aot"][0]
        extended = LIB + self.symbols["extended_unit"][0]
        require(sha(bytes(u.mem_read(unit, 14896))) == MAIN_SHA256, "mapped unit is not stock")
        require(bytes(u.mem_read(cache, 24)) == struct.pack("<3Q", unit, aot, 0), "mapped stock cache is wrong")
        if case == "bad_build_note": u.mem_write(APP + self.note_va + 16, b"X")
        if case == "bad_unit": u.mem_write(unit + 501, b"X")
        if case == "bad_cache_data": u.mem_write(cache, pack64(unit + 8))
        if case == "bad_cache_aot": u.mem_write(cache + 8, pack64(aot + 8))
        if case == "bad_cache_unused": u.mem_write(cache + 16, pack64(1))
        if case == "bad_aot":
            at = aot + 8 * (0 if aot_index is None else aot_index)
            u.mem_write(at, pack64(struct.unpack("<Q", bytes(u.mem_read(at, 8)))[0] ^ 1))
        if case == "bad_payload_magic": u.mem_write(extended, b"X")

        def guarded_hash():
            digest = hashlib.sha256()
            # Entire mapped stock image, including BSS, excluding only data pointer.
            for begin, end in ((APP, cache), (cache + 8, APP + app_size)):
                digest.update(bytes(u.mem_read(begin, end - begin)))
            return digest.hexdigest()

        before_guard = guarded_hash()
        before_pointer = bytes(u.mem_read(cache, 8))
        before_cache_tail = bytes(u.mem_read(cache + 8, 16))
        before_aot = bytes(u.mem_read(aot, 1008))
        u.mem_write(SCRATCH, b"1\0")
        u.mem_write(SCRATCH + 16, b"0\0")
        errno_at, phdr_at, info_at, name_at = SCRATCH + 32, SCRATCH + 0x100, SCRATCH + 0x500, SCRATCH + 0x800
        loads = [list(fields) for fields, _ in self.loads]
        if case == "bad_load_flags": loads[0][1] ^= 2
        if case == "bad_load_address": loads[1][3] += 4096
        if case == "bad_load_size": loads[0][5] -= 8
        if case == "bad_load_order": loads.reverse()
        if case == "missing_load": loads.pop()
        if case == "extra_load": loads.append(loads[0])
        for i, fields in enumerate(loads): u.mem_write(phdr_at + i * 56, struct.pack("<II6Q", *fields))
        u.mem_write(name_at, b"/system/lib64/unrelated.so\0")
        u.mem_write(name_at + 128, b"/system/bin/camera-gui\0")
        app_name = name_at if case == "wrong_image_name" else (0 if case != "named_image" else name_at + 128)
        # First a real unrelated-library callback (must return 0), then app callback.
        infos = [(LIB, name_at, phdr_at, len(loads)),
                 (0 if case == "zero_base" else APP, app_name,
                  0 if case == "null_phdr" else phdr_at, len(loads))]
        for i, fields in enumerate(infos): u.mem_write(info_at + i * 32, struct.pack("<QQQH6x", *fields))
        state = {"status": "", "writes": 0, "seeks": 0, "attempt": False, "position": 0,
                 "exit": None, "callbacks": 0, "imageInstructions": 0, "instructions": 0,
                 "opens": [], "openFlags": [], "closes": [], "nativeMemoryWrites": 0,
                 "statusCreated": False, "statusWrites": 0, "statusPath": None,
                 "existingStatus": b"preserve existing diagnostic inode and hardlink target\n",
                 "minSp": SCRATCH + 0x1F000}
        existing_status = state["existingStatus"]
        stack = SCRATCH + 0x1F000
        sentinels = {UC_ARM64_REG_X18: 0x1818181818181818}
        for reg in (getattr(arm64_const, "UC_ARM64_REG_X" + str(i)) for i in range(19, 30)):
            sentinels[reg] = 0xAA00000000000000 + reg
        for reg, value in sentinels.items(): u.reg_write(reg, value)
        u.reg_write(UC_ARM64_REG_SP, stack)
        u.reg_write(UC_ARM64_REG_LR, STUBS)
        callback_return = STUBS + 0x10
        callback_state = {}

        def cstr(address):
            result = bytearray()
            for i in range(4096):
                char = bytes(u.mem_read(address + i, 1))
                if char == b"\0": return result.decode("utf-8")
                result.extend(char)
            raise ValueError("unterminated simulated C string")

        def ret(value):
            u.reg_write(UC_ARM64_REG_X0, value & MASK)
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

        def enter_callback(index):
            state["callbacks"] += 1
            callback_state["index"] = index
            callback_state["active"] = True
            u.reg_write(UC_ARM64_REG_X0, info_at + index * 32)
            u.reg_write(UC_ARM64_REG_X1, 16 if case == "short_dl_info" else 32)
            u.reg_write(UC_ARM64_REG_X2, callback_state["data"])
            u.reg_write(UC_ARM64_REG_LR, callback_return)
            u.reg_write(UC_ARM64_REG_PC, callback_state["function"])

        def native_write(uc, access, address, size, value, opaque):
            require(SCRATCH + 0x10000 <= address and address + size <= stack,
                    "native code wrote outside its stack")
            state["nativeMemoryWrites"] += 1

        def call(uc, address, size, opaque):
            function = imports.get(address)
            require(address in self.native_instruction_pcs or function is not None
                    or (address == callback_return and callback_state.get("active") is True),
                    "execution PC outside verified native code: " + hex(address))
            state["instructions"] += 1
            require(uc.reg_read(UC_ARM64_REG_X18) == sentinels[UC_ARM64_REG_X18], "x18 clobbered")
            sp = uc.reg_read(UC_ARM64_REG_SP)
            require(SCRATCH + 0x10000 <= sp <= stack and sp % 16 == 0, "stack bounds/alignment")
            state["minSp"] = min(state["minSp"], sp)
            image_begin, image_size = self.symbols["image"]
            if LIB + image_begin <= address < LIB + image_begin + image_size:
                state["imageInstructions"] += 1
            if address == callback_return:
                callback_result = uc.reg_read(UC_ARM64_REG_X0)
                if callback_result == 0 and callback_state["index"] + 1 < len(infos):
                    enter_callback(callback_state["index"] + 1)
                else:
                    callback_state["active"] = False
                    uc.reg_write(UC_ARM64_REG_LR, callback_state["return"])
                    ret(callback_result)
                return
            if function is None: return
            a, b, c = [uc.reg_read(reg) for reg in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            value = 0
            if function == "getenv":
                require(cstr(a) == "X2DII_MENU_EXTENSION", "unexpected environment read")
                value = 0 if case == "not_enabled" else SCRATCH + (16 if case == "env_zero" else 0)
            elif function == "readlink":
                require(cstr(a) == "/proc/self/exe", "unexpected readlink")
                text = b"/system/bin/other" if case == "wrong_program" else b"/system/bin/camera-gui"
                if case == "readlink_fail": value = -1
                elif case == "readlink_truncated": uc.mem_write(b, b"X" * c); value = c
                else: uc.mem_write(b, text); value = len(text)
            elif function == "strcmp": value = 0 if cstr(a) == cstr(b) else 1
            elif function == "memcmp": value = 0 if bytes(uc.mem_read(a, c)) == bytes(uc.mem_read(b, c)) else 1
            elif function == "__errno": value = errno_at
            elif function == "getpid": value = pid
            elif function == "dl_iterate_phdr":
                require(a == LIB + self.symbols["image"][0], "wrong actual callback")
                callback_state.update(function=a, data=b, **{"return": uc.reg_read(UC_ARM64_REG_LR)})
                enter_callback(0)
                return
            elif function == "open":
                path = cstr(a); state["opens"].append(path)
                state["openFlags"].append({"path": path, "flags": b})
                require(b & CLOEXEC, "O_CLOEXEC missing")
                if path == "/blackbox/x2dii-menu.disable":
                    require(b & NONBLOCK, "disable FIFO would block without O_NONBLOCK")
                    require(b == NOFOLLOW | CLOEXEC | NONBLOCK, "disable path flags")
                    value = 3 if case in ("disabled", "disable_fifo", "disable_directory", "disable_hardlink") else -1
                    error = {"disable_permission": 13, "disable_symlink": 40, "disable_io": 5,
                             "disable_socket": 6}.get(case, 2)
                    uc.mem_write(errno_at, struct.pack("<I", error))
                elif path == "/tmp/x2dii-menu.attempt":
                    require(b == 1 | CREAT | EXCL | NOFOLLOW | CLOEXEC | NONBLOCK and c == 0o600, "marker flags/mode")
                    value = -1 if case in ("retry", "marker_permission", *MARKER_EXISTING_CASES) else 4
                    state["attempt"] = value == 4
                elif path == "/proc/self/mem":
                    require(b == 2 | 524288, "process-memory flags")
                    value = -1 if case == "mem_open_fail" else 5
                elif path.startswith("/tmp/x2dii-menu.status"):
                    state["statusPath"] = path
                    require(path == "/tmp/x2dii-menu.status-" + str(pid), "status path must be unique to positive PID")
                    require(b & NONBLOCK, "status FIFO could block without O_NONBLOCK")
                    require(b == 1 | CREAT | EXCL | NOFOLLOW | CLOEXEC | NONBLOCK and c == 0o600,
                            "status must use exclusive nonblocking creation without truncation")
                    # Linux O_CREAT|O_EXCL refuses every existing final path object,
                    # including hardlinks, FIFOs, and dangling or normal symlinks.
                    existing = status_case in STATUS_EXISTING_CASES
                    value = -1 if existing or status_case == "status_open_fail" else 6
                    state["statusCreated"] = value == 6
                    if value < 0:
                        uc.mem_write(errno_at, struct.pack("<I", 17 if existing else 13))
                else: raise ValueError("unexpected open: " + path)
            elif function == "close":
                state["closes"].append(a)
                value = -1 if ((a == 4 and case == "marker_close_fail") or
                               (a == 5 and case == "mem_close_fail") or
                               (a == 6 and status_case == "status_close_fail")) else 0
            elif function == "lseek":
                require(a == 5 and b == cache and c == 0, "write seek outside data pointer")
                state["seeks"] += 1
                fail = (case == "seek_fail" and state["seeks"] == 1) or (case == "restore_seek_fail" and state["seeks"] == 2)
                state["position"] = b
                value = -1 if fail else b
            elif function == "write":
                if a == 6:
                    require(state["statusCreated"], "diagnostic write targets an existing file")
                    state["statusWrites"] += 1
                    value = -1 if status_case == "status_write_fail" else (3 if status_case == "status_short_write" else c)
                    if value > 0: state["status"] += bytes(uc.mem_read(b, value)).decode("utf-8")
                else:
                    require(a == 5 and c == 8 and state["position"] == cache, "write escaped single cache pointer")
                    state["writes"] += 1
                    first = state["writes"] == 1
                    value = c
                    if first and case.startswith("partial_"): value = int(case.split("_")[1])
                    if first and case in ("restore_write_fail", "restore_seek_fail", "restore_readback_fail"): value = 4
                    if first and case == "write_fail": value = -1
                    if not first and case == "restore_write_fail": value = -1
                    if value > 0:
                        uc.mem_write(cache, bytes(uc.mem_read(b, value)))
                    if (first and case == "readback_fail") or (not first and case == "restore_readback_fail"):
                        uc.mem_write(cache, pack64(0xDEADBEEF12345678))
            elif function == "_exit":
                state["exit"] = a
                uc.emu_stop()
                return
            else: raise ValueError("unimplemented libc stub: " + function)
            ret(value)

        u.hook_add(UC_HOOK_CODE, call)
        u.hook_add(UC_HOOK_MEM_WRITE, native_write)
        init = self.elf.get_section_by_name(".init_array")["sh_addr"]
        start = struct.unpack("<Q", bytes(u.mem_read(LIB + init, 8)))[0]
        require(start == LIB + self.symbols["install"][0], "constructor entry mismatch")
        u.emu_start(start, STUBS, count=2_000_000)
        terminated = state["exit"] is not None
        require(terminated or u.reg_read(UC_ARM64_REG_PC) == STUBS, "constructor did not finish")
        if not terminated:
            require(u.reg_read(UC_ARM64_REG_SP) == stack, "stack not restored")
            for reg, expected in sentinels.items():
                require(u.reg_read(reg) == expected, "callee-saved register not restored")
        after_guard = guarded_hash()
        require(after_guard == before_guard, "unrelated original image changed")
        require(bytes(u.mem_read(cache + 8, 16)) == before_cache_tail, "cache AOT/unused changed")
        require(bytes(u.mem_read(aot, 1008)) == before_aot, "AOT table changed")
        after_pointer = bytes(u.mem_read(cache, 8))
        early = {"not_enabled", "env_zero", "wrong_program", "readlink_fail", "readlink_truncated"}
        if case not in early and not case.startswith("disable"):
            require(state["imageInstructions"] > 0 and state["callbacks"] == 2, "actual image callback was not executed")
        success = case in ("success", "named_image", "mem_close_fail", *STATUS_FAILURE_CASES, *STATUS_EXISTING_CASES)
        fatal = case in ("restore_seek_fail", "restore_write_fail", "restore_readback_fail")
        if success:
            require(after_pointer == pack64(extended), "successful data pointer not installed")
            require(state["writes"] == 1 and state["attempt"], "successful write/marker count")
        elif fatal:
            require(terminated and state["exit"] == 78, "bad pointer continued instead of _exit(78)")
        else:
            require(not terminated and after_pointer == before_pointer, "failed case changed original pointer")
        require(state["existingStatus"] == existing_status, "existing status inode/target was changed")
        if status_case in STATUS_EXISTING_CASES or status_case == "status_open_fail":
            require(not state["statusCreated"] and state["statusWrites"] == 0 and 6 not in state["closes"],
                    "rejected diagnostic file was used")
        if case == "disable_fifo":
            require(state["writes"] == 0 and not state["attempt"] and state["callbacks"] == 0,
                    "FIFO disable path allowed native mutation")
        expected_status = self.expected_status(case)
        if pid <= 0 or status_case in (*STATUS_EXISTING_CASES, "status_open_fail", "status_write_fail"):
            expected_status = ""
        elif status_case == "status_short_write":
            expected_status = expected_status[:3]
        require(state["status"] == expected_status, "wrong status for " + case + ": " + repr(state["status"]))
        return {"case": case, "aotIndex": aot_index, "result": "PASS", "status": state["status"].strip(),
                "memoryWrites": state["writes"], "markerCreated": state["attempt"], "exitCode": state["exit"],
                "imageCallbackInvocations": state["callbacks"], "imageInstructions": state["imageInstructions"],
                "executedInstructions": state["instructions"], "maxStackBytes": stack - state["minSp"],
                "x18Preserved": True, "calleeSavedAndStackRestored": not terminated,
                "originalImageExceptDataPointerSha256": after_guard, "aotAndUnusedPreserved": True,
                "pid": pid, "diagnosticCase": diagnostic_case,
                "statusPath": state["statusPath"], "statusCreated": state["statusCreated"],
                "statusWrites": state["statusWrites"], "existingStatusPreserved": True,
                "opens": state["opens"], "openFlags": state["openFlags"], "closes": state["closes"]}

    @staticmethod
    def expected_status(case: str) -> str:
        if case in ("not_enabled", "env_zero", "wrong_program", "readlink_fail", "readlink_truncated",
                    "status_open_fail", "status_write_fail", *STATUS_EXISTING_CASES):
            return ""
        if case in ("disabled", "disable_fifo", "disable_directory", "disable_hardlink"): return "DISABLED\n"
        if case.startswith("disable_"): return "DISABLE_CHECK_FAILED\n"
        if case == "status_short_write": return "MEN"
        if case in ("bad_load_flags", "bad_load_address", "bad_load_size", "bad_load_order", "missing_load",
                    "extra_load", "wrong_image_name", "zero_base", "null_phdr", "short_dl_info"):
            return "IMAGE_LAYOUT_MISMATCH\n"
        if case in ("bad_build_note", "bad_unit", "bad_cache_data", "bad_cache_aot", "bad_cache_unused"):
            return "BUILD_MISMATCH\n"
        if case == "bad_aot": return "AOT_MISMATCH\n"
        if case == "bad_payload_magic": return "PAYLOAD_MISMATCH\n"
        if case in ("retry", "marker_permission", *MARKER_EXISTING_CASES): return "SKIPPED_RETRY_OR_MARKER_ERROR\n"
        if case == "marker_close_fail": return "MARKER_CLOSE_FAILED\n"
        if case == "mem_open_fail": return "MEMORY_OPEN_FAILED\n"
        if case.startswith("restore_"): return "RESTORE_FAILED_EXIT\n"
        if case.startswith("partial_") or case in ("seek_fail", "write_fail", "readback_fail"):
            return "WRITE_FAILED_RESTORED\n"
        return "MENU_POINTER_READY\n"


CASES = ("success", "named_image", "not_enabled", "env_zero", "disabled", "disable_fifo",
         "disable_directory", "disable_hardlink", "disable_socket", "disable_permission",
         "disable_symlink", "disable_io", "wrong_program", "readlink_fail", "readlink_truncated",
         "bad_load_flags", "bad_load_address", "bad_load_size", "bad_load_order", "missing_load", "extra_load",
         "wrong_image_name", "zero_base", "null_phdr", "short_dl_info", "bad_build_note", "bad_unit",
         "bad_cache_data", "bad_cache_aot", "bad_cache_unused", "bad_payload_magic", "retry", "marker_permission",
         "marker_close_fail", "mem_open_fail", "seek_fail", "write_fail", "readback_fail",
         "restore_seek_fail", "restore_write_fail", "restore_readback_fail", "mem_close_fail",
         *STATUS_FAILURE_CASES, *STATUS_EXISTING_CASES, *MARKER_EXISTING_CASES,
         *("partial_" + str(i) for i in range(8)))


def runtime_identity() -> dict:
    binding = Path(unicorn.__file__).resolve()
    implementation = Path(unicorn.unicorn.__file__).resolve()
    native = Path(unicorn.unicorn._uc._name).resolve()
    require(binding.is_relative_to(VENDOR.resolve()) and native.is_relative_to(VENDOR.resolve()), "wrong Unicorn runtime")
    return {"bindingVersion": unicorn.__version__, "nativeVersion": list(unicorn.uc_version()),
            "bindingPath": str(binding), "bindingSha256": sha256_file(binding),
            "implementationPath": str(implementation), "implementationSha256": sha256_file(implementation),
            "nativeLibraryPath": str(native), "nativeLibrarySha256": sha256_file(native),
            "capstoneVersion": capstone.__version__}


def write_report(report: dict, output: Path) -> Path:
    return write_output(output, (json.dumps(report, indent=2) + "\n").encode("utf-8"))


def main() -> int:
    harness = NativeHarness()
    cases = [harness.run(case) for case in CASES]
    # Check every AOT word, including all function indices, relocated pointers,
    # and the zero terminator, instead of only one convenient entry.
    cases += [harness.run("bad_aot", aot_index=i) for i in range(126)]
    cases += [harness.run("success", pid=pid) for pid in (1, 9, 10, 2147483647, 0, -1)]
    cases += [harness.run("restore_write_fail", diagnostic_case=fault)
              for fault in (*STATUS_FAILURE_CASES, *STATUS_EXISTING_CASES)]
    report = {"result": "PASS", "status": "LOCAL_EMULATION_ONLY", "installable": False,
              "cameraValidated": False, "cameraAccesses": 0, "runtime": runtime_identity(),
              "nativeLibrarySha256": sha(harness.raw), "guiSha256": GUI_SHA256,
              "stockUnitSha256": MAIN_SHA256, "extendedUnitSha256": harness.build_report["extendedUnitSha256"],
              "sourceSha256": harness.build_report["sourceSha256"], "unwind": harness.unwind,
              "harnessSha256": sha256_file(Path(__file__)), "pythonOptimized": bool(sys.flags.optimize),
              "caseCount": len(cases), "cases": cases,
              "limitations": ["simulated libc, dynamic loader, /proc/self/mem and files",
                              "no Qt engine, GUI, camera, Android linker or actual filesystem execution",
                              "unwind tables decoded and stack checked; exception unwinding not executed"]}
    output = PROJECT / "build/native-validation.json"
    write_report(report, output)
    print(json.dumps({k: report[k] for k in ("result", "status", "caseCount", "nativeLibrarySha256", "runtime")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
