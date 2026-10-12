"""Read the pinned X2D II ELF and validate Qt 6.8.2 compiled QML data.

Layout source: qt/qtdeclarative v6.8.2, src/qml/common/qv4compileddata_p.h.
This is a bounded offline reader, not a Qt runtime or an ABI qualification.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

GUI_SHA256 = "b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b"
MAIN_SYMBOL = "_ZN21QmlCacheGeneratedCode39_qt_qml_app_qml_mainmenu_MainScreen_qml7qmlDataE"
MAIN_ADDRESS = 0x200CCD0
MAIN_SIZE = 14896
MAIN_SHA256 = "6e63afc292266256be04e3b09fc10f8359c98632dfd35ada9a71b9c36d9fabeb"
QT_VERSION = 0x60802
DATA_VERSION = 66
HEADER_SIZE = 248
OBJECT_SIZE = 84
BINDING_SIZE = 24
TABLE_NAMES = ("string", "function", "class", "template", "block", "lookup",
               "regexp", "constant", "js_class", "translation", "local_export",
               "indirect_export", "star_export", "import_entry", "module_request")
TABLE_WIDTHS = (4, 4, 4, 4, 4, 4, 4, 8, 4, 16, 20, 20, 20, 16, 4)


class ValidationError(ValueError):
    """Input is not a supported, bounded compiled unit."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def span(data: bytes, offset: int, size: int, label: str,
         lower: int = 0, upper: int | None = None) -> None:
    ceiling = len(data) if upper is None else upper
    require(0 <= lower <= offset <= ceiling <= len(data)
            and 0 <= size <= ceiling - offset, f"{label}: out of bounds")


def u16(data: bytes, offset: int) -> int:
    span(data, offset, 2, "u16")
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    span(data, offset, 4, "u32")
    return struct.unpack_from("<I", data, offset)[0]


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_file_hash(path: Path, expected: str) -> str:
    actual = sha256_file(path)
    require(actual == expected, f"ELF SHA256 mismatch: {actual}")
    return actual


def read_main_screen(path: Path) -> bytes:
    """Hash a local ELF by streaming; read only its bounded MainScreen symbol."""
    from elftools.elf.elffile import ELFFile

    # Validate and extract from one open file, preventing a pathname swap between opens.
    with path.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == GUI_SHA256,
                "ELF SHA256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        require(elf.elfclass == 64 and elf.little_endian
                and elf.header["e_machine"] == "EM_AARCH64", "ELF must be LE64 AArch64")
        matches = set()
        for name in (".symtab", ".dynsym"):
            section = elf.get_section_by_name(name)
            if section is not None:
                for symbol in section.get_symbol_by_name(MAIN_SYMBOL) or []:
                    require(symbol["st_info"]["type"] == "STT_OBJECT", "unit symbol is not an object")
                    matches.add((int(symbol["st_value"]), int(symbol["st_size"])))
        require(matches == {(MAIN_ADDRESS, MAIN_SIZE)}, "MainScreen symbol identity mismatch")
        mappings = []
        stream.seek(0, 2)
        file_size = stream.tell()
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            base, size = int(segment["p_vaddr"]), int(segment["p_filesz"])
            if base <= MAIN_ADDRESS and MAIN_ADDRESS + MAIN_SIZE <= base + size:
                offset = int(segment["p_offset"]) + MAIN_ADDRESS - base
                require(0 <= offset <= file_size - MAIN_SIZE, "symbol exceeds file")
                mappings.append(offset)
        require(len(mappings) == 1, "symbol must have exactly one complete file-backed mapping")
        stream.seek(mappings[0])
        data = stream.read(MAIN_SIZE)
    require(hashlib.sha256(data).hexdigest() == MAIN_SHA256, "MainScreen unit SHA256 mismatch")
    parse_unit(data)
    return data


@dataclass(frozen=True)
class ObjectRecord:
    offset: int
    end: int
    bindings_offset: int
    binding_count: int
    bindings: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class Unit:
    data: bytes
    strings: tuple[str, ...]
    string_offsets: tuple[int, ...]
    tables: dict[str, tuple[int, int]]
    qml_offset: int
    object_offsets: tuple[int, ...]
    objects: tuple[ObjectRecord, ...]
    checksum_mode: str


def parse_unit(data: bytes) -> Unit:
    """Validate all tables, record-relative spans, and serialized index domains.

    Does not disassemble bytecode or prove a vendor runtime accepts the result.
    The stock unit's generated checksum precedes StaticData/PendingTypeCompilation
    flags. Only that exact two-bit normalization is accepted as a second form.
    """
    span(data, 0, HEADER_SIZE, "unit header")
    require(data[:8] == b"qv4cdata", "invalid unit magic")
    require(u32(data, 8) == DATA_VERSION, "unsupported QV4 data version")
    require(u32(data, 12) == QT_VERSION, "unsupported Qt version (requires 6.8.2)")
    require(u32(data, 24) == len(data), "unit size mismatch")
    checksum_mode = "serialized"
    if hashlib.md5(data[92:]).digest() != data[76:92]:
        normalized = bytearray(data[92:])
        struct.pack_into("<I", normalized, 16, u32(data, 108) & ~0x22)
        require(hashlib.md5(normalized).digest() == data[76:92], "unit MD5 mismatch")
        checksum_mode = "before_static_and_pending_flags"

    tables = {}
    starts = {len(data)}
    fixed_regions = []

    def add_start(offset: int, label: str) -> None:
        require(offset not in starts, f"{label}: aliased record/table start")
        starts.add(offset)

    for index, (name, width) in enumerate(zip(TABLE_NAMES, TABLE_WIDTHS)):
        count, offset = struct.unpack_from("<II", data, 112 + index * 8)
        span(data, offset, count * width, f"{name} table", HEADER_SIZE)
        require(offset % (8 if name == "constant" else 4) == 0,
                f"{name} table alignment")
        tables[name] = count, offset
        if count:
            add_start(offset, name)
            fixed_regions.append((offset, count * width, name))

    # These features are absent from the pinned MainScreen. Reject them rather
    # than claiming complete semantic support for all Qt/JavaScript unit kinds.
    for name in ("class", "template", "js_class", "translation", "local_export",
                 "indirect_export", "star_export", "import_entry", "module_request"):
        require(tables[name][0] == 0, f"unsupported table in MainScreen profile: {name}")

    def offsets(name: str, minimum: int) -> tuple[int, ...]:
        count, table = tables[name]
        result = tuple(u32(data, table + index * 4) for index in range(count))
        require(len(set(result)) == len(result), f"duplicate {name} record offset")
        for offset in result:
            span(data, offset, minimum, f"{name} record", HEADER_SIZE)
            require(offset % 8 == 0, f"{name} record alignment")
            add_start(offset, name)
        return result

    string_offsets = offsets("string", 6)
    function_offsets = offsets("function", 56)
    block_offsets = offsets("block", 12)
    class_offsets = offsets("class", 24)
    template_offsets = offsets("template", 4)
    js_class_offsets = offsets("js_class", 4)
    qml = u32(data, 244)
    span(data, qml, 16, "QmlUnit", HEADER_SIZE)
    require(qml % 8 == 0, "QmlUnit alignment")
    add_start(qml, "QmlUnit")
    fixed_regions.append((qml, 16, "QmlUnit"))
    n_imports, imports_rel, n_objects, objects_rel = struct.unpack_from("<4I", data, qml)
    require(n_objects > 0, "QmlUnit has no root object")
    for count, rel, width, name in ((n_imports, imports_rel, 20, "imports"),
                                  (n_objects, objects_rel, 4, "objects")):
        span(data, qml + rel, count * width, f"QML {name}", qml + 16)
        require(rel % 4 == 0, f"QML {name} alignment")
        if count:
            add_start(qml + rel, "QML " + name)
            fixed_regions.append((qml + rel, count * width, "QML " + name))
    object_offsets = tuple(qml + u32(data, qml + objects_rel + i * 4)
                           for i in range(n_objects))
    require(len(set(object_offsets)) == n_objects, "duplicate QML object offset")
    for offset in object_offsets:
        span(data, offset, OBJECT_SIZE, "object", qml + 16)
        require(offset % 8 == 0, "object alignment")
        add_start(offset, "object")
    ordered_starts = sorted(starts)

    def record_end(offset: int) -> int:
        return next(end for end in ordered_starts if end > offset)

    for offset, size, label in fixed_regions:
        span(data, offset, size, label, offset, record_end(offset))

    def disjoint(regions: list[tuple[int, int, str]]) -> None:
        ordered = sorted((offset, offset + size, label) for offset, size, label in regions if size)
        for left, right in zip(ordered, ordered[1:]):
            require(left[1] <= right[0], f"overlapping {left[2]} and {right[2]}")

    def relative(base: int, rel: int, count: int, width: int,
                 minimum: int, label: str) -> int:
        # An empty table may have the null offset; non-null offsets are still bounded.
        if not count and not rel:
            return base
        require(rel % 4 == 0, f"{label}: relative alignment")
        span(data, base + rel, count * width, label, base + minimum, record_end(base))
        return base + rel

    strings = []
    for offset in string_offsets:
        length = struct.unpack_from("<i", data, offset)[0]
        require(length >= 0, "negative string length")
        span(data, offset + 4, length * 2 + 2, "UTF-16 string", offset + 4, record_end(offset))
        require(data[offset + 4 + length * 2:offset + 6 + length * 2] == b"\0\0",
                "string lacks terminator")
        try:
            strings.append(data[offset + 4:offset + 4 + length * 2].decode("utf-16le"))
        except UnicodeDecodeError as error:
            raise ValidationError("invalid UTF-16 string") from error

    def index(value: int, count: int, label: str) -> None:
        require(0 <= value < count, f"{label}: index out of bounds")

    def string_index(value: int, label: str) -> None:
        index(value, len(strings), label)

    def parameter_type(encoded: int, label: str) -> None:
        if encoded & 1:
            require(encoded >> 2 <= 14, f"{label}: unknown common type")
        else:
            string_index(encoded >> 2, label)

    def parameters(base: int, count: int, label: str) -> None:
        for i in range(count):
            string_index(u32(data, base + i * 8), label)
            parameter_type(u32(data, base + i * 8 + 4), label)

    string_index(u32(data, 236), "source file")
    string_index(u32(data, 240), "final URL")
    root_function = u32(data, 232)
    require(root_function == 0xFFFFFFFF or root_function < len(function_offsets), "root function index")
    for base in function_offsets:
        string_index(u32(data, base + 8), "function name")
        parameter_type(u32(data, base + 20), "function return type")
        nested = u32(data, base + 32)
        require(nested == 0xFFFFFFFF or nested < len(function_offsets), "nested function index")
        formals = relative(base, u32(data, base + 16), u16(data, base + 14), 8, 56, "formals")
        parameters(formals, u16(data, base + 14), "formal")
        locals_rel, locals_count = u32(data, base + 24), u16(data, base + 28)
        local_table = relative(base, locals_rel, locals_count, 4, 56, "locals")
        for i in range(locals_count):
            string_index(u32(data, local_table + i * 4), "local")
        lines = u16(data, base + 30)
        line_table = relative(base, locals_rel + locals_count * 4, lines, 12, 56, "source lines")
        labels = u32(data, base + 44)
        label_table = relative(base, locals_rel + locals_count * 4 + lines * 12,
                               labels, 4, 56, "label info")
        # Function::code(), despite the stale 'absolute' comment in the Qt header,
        # adds codeOffset to this Function, not to the Unit.
        code = relative(base, u32(data, base), u32(data, base + 4), 1, 56, "function code")
        disjoint([(formals, u16(data, base + 14) * 8, "formals"),
                  (local_table, locals_count * 4, "locals"), (line_table, lines * 12, "source lines"),
                  (label_table, labels * 4, "label info"), (code, u32(data, base + 4), "code")])

    for base in block_offsets:
        count = u32(data, base)
        table = relative(base, u32(data, base + 4), count, 4, 12, "block locals")
        for i in range(count):
            string_index(u32(data, table + i * 4), "block local")
    for base in class_offsets:
        string_index(u32(data, base), "class name")
        index(u32(data, base + 4), len(block_offsets), "class scope")
        index(u32(data, base + 8), len(function_offsets), "class constructor")
        count = u32(data, base + 12) + u32(data, base + 16)
        table = relative(base, u32(data, base + 20), count, 12, 24, "methods")
        for i in range(count):
            string_index(u32(data, table + i * 12), "method name")
            require(u32(data, table + i * 12 + 4) <= 2, "method type")
            index(u32(data, table + i * 12 + 8), len(function_offsets), "method function")
    for base in template_offsets + js_class_offsets:
        is_template = base in template_offsets
        count = u32(data, base) * (2 if is_template else 1)
        table = relative(base, 4, count, 4, 4, "template/JS class strings")
        for i in range(count):
            value = u32(data, table + i * 4)
            string_index(value if is_template else value & 0x7FFFFFFF, "template/JS class name")
    for name, shift in (("lookup", 4), ("regexp", 5)):
        count, table = tables[name]
        for i in range(count):
            string_index(u32(data, table + i * 4) >> shift, name)
    count, table = tables["translation"]
    if count:
        span(data, table, count * 16 + 4, "translations and context")
        context = u32(data, table + count * 16)
        require(context == 0xFFFFFFFF or context < len(strings), "translation context")
    for i in range(count):
        string_index(u32(data, table + i * 16), "translation string")
        string_index(u32(data, table + i * 16 + 4), "translation comment")
        context = u32(data, table + i * 16 + 12)
        require(context == 0xFFFFFFFF or context < len(strings), "translation context")
    for name in ("local_export", "indirect_export", "star_export", "import_entry"):
        count, table = tables[name]
        width = 16 if name == "import_entry" else 20
        for i in range(count):
            for field in range(width // 4 - 1):
                string_index(u32(data, table + i * width + field * 4), name)
    count, table = tables["module_request"]
    for i in range(count):
        string_index(u32(data, table + i * 4), "module request")
    for i in range(n_imports):
        base = qml + imports_rel + i * 20
        require(1 <= u32(data, base) <= 4, "QML import type")
        string_index(u32(data, base + 4), "QML import URI")
        string_index(u32(data, base + 8), "QML import qualifier")

    objects = []
    for base in object_offsets:
        string_index(u32(data, base), "inherited type")
        string_index(u32(data, base + 4), "object id name")
        object_tables = {}
        object_regions = []
        for name, count_at, offset_at, width, count16 in (
                ("functions", 16, 20, 4, True), ("properties", 18, 24, 12, True),
                ("aliases", 32, 28, 20, True), ("enums", 34, 36, 4, True),
                ("signals", 44, 40, 4, True), ("bindings", 46, 48, 24, True),
                ("named objects", 52, 56, 4, False), ("inline components", 72, 68, 12, True),
                ("required properties", 80, 76, 4, True)):
            count = (u16 if count16 else u32)(data, base + count_at)
            table = relative(base, u32(data, base + offset_at), count, width, OBJECT_SIZE, name)
            object_tables[name] = count, table
            object_regions.append((table, count * width, name))
        disjoint(object_regions)
        default_property = u32(data, base + 12)
        default_domain = "aliases" if u32(data, base + 8) & 0x8000 else "properties"
        require(default_property == 0xFFFFFFFF or default_property < object_tables[default_domain][0],
                "default property/alias index")
        count, table = object_tables["functions"]
        for i in range(count):
            index(u32(data, table + i * 4), len(function_offsets), "object function")
        count, table = object_tables["properties"]
        for i in range(count):
            string_index(u32(data, table + i * 12), "property name")
            encoded = u32(data, table + i * 12 + 4)
            if encoded & 0x20000000:
                require(encoded & 0x0FFFFFFF <= 14, "property common type")
            else:
                string_index(encoded & 0x0FFFFFFF, "property type")
        count, table = object_tables["aliases"]
        for i in range(count):
            encoded = u32(data, table + i * 20)
            string_index(encoded & 0x1FFFFFFF, "alias name")
            if not encoded & 0x40000000:
                string_index(u32(data, table + i * 20 + 4), "alias ID")
                string_index(u32(data, table + i * 20 + 8), "alias property")
        for name in ("signals", "enums"):
            count, table = object_tables[name]
            for i in range(count):
                item = relative(base, u32(data, table + i * 4), 1, 12, OBJECT_SIZE, name)
                string_index(u32(data, item), name)
                elements = u32(data, item + 4)
                relative(base, item + 12 - base, elements, 8 if name == "signals" else 12,
                         OBJECT_SIZE, name + " elements")
                object_regions.append((item, 12 + elements * (8 if name == "signals" else 12),
                                       name + " record"))
                if name == "signals":
                    parameters(item + 12, elements, "signal parameter")
                else:
                    for j in range(elements):
                        string_index(u32(data, item + 12 + j * 12), "enum value")
        count, table = object_tables["named objects"]
        for i in range(count):
            index(u32(data, table + i * 4), n_objects, "named object")
        count, table = object_tables["inline components"]
        for i in range(count):
            index(u32(data, table + i * 12), n_objects, "inline component")
            string_index(u32(data, table + i * 12 + 4), "inline component name")
        count, table = object_tables["required properties"]
        for i in range(count):
            string_index(u32(data, table + i * 4), "required property name")
        count, table = object_tables["bindings"]
        bindings = tuple(struct.unpack_from("<6I", data, table + i * BINDING_SIZE) for i in range(count))
        for prop, flags_type, value, text, _location, _value_location in bindings:
            string_index(prop, "binding property")
            string_index(text, "binding string")
            kind = flags_type >> 16
            require(kind <= 10, "unknown binding type")
            if kind == 1:
                require(value in (0, 1), "invalid boolean binding")
            if kind in (8, 9, 10):
                index(value, n_objects, "binding object")
            if kind == 7:
                index(value, len(function_offsets), "binding script")
            if kind == 2:
                index(value, tables["constant"][0], "binding constant")
            if kind in (5, 6):
                index(value, tables["translation"][0], "binding translation")
        disjoint(object_regions)
        objects.append(ObjectRecord(base, record_end(base), table, count, bindings))
    return Unit(data, tuple(strings), string_offsets, tables, qml,
                object_offsets, tuple(objects), checksum_mode)
