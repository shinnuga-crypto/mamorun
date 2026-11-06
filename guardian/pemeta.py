"""実行ファイル（PE）を読むだけの解析。OSに触れず、ファイルを実行もしない。

悪意あるファイルも読むので、すべての位置と長さを確かめ、壊れていても例外を外へ出さない。
"""
from __future__ import annotations

import math
import mmap
import struct
from dataclasses import dataclass, field

ENTROPY_SAMPLE = 2 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 512
MAX_IMPORT_FUNCS = 20000
MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARM"}
SUBSYSTEMS = {1: "ネイティブ", 2: "GUI", 3: "コンソール", 9: "Windows CE", 10: "EFI"}
SCN_EXECUTE = 0x20000000
SCN_WRITE = 0x80000000
DLL_ASLR = 0x0040
DLL_DEP = 0x0100
DLL_CFG = 0x4000
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".pelock": "PELock",
}


@dataclass
class Section:
    name: str
    raw_size: int
    virtual_size: int
    entropy: float
    executable: bool
    writable: bool


@dataclass
class PeInfo:
    machine: str = "不明"
    is_64bit: bool = False
    is_dll: bool = False
    is_dotnet: bool = False
    timestamp: int = 0
    subsystem: str = "不明"
    sections: list[Section] = field(default_factory=list)
    entry_section: str | None = None
    entry_outside_sections: bool = False
    overlay_size: int = 0
    cert_size: int = 0
    cert_slack: int = 0  # 署名領域のうち、署名の外にある余分なデータ
    imports: dict[str, list[str]] = field(default_factory=dict)
    import_count: int = 0
    aslr: bool = False
    dep: bool = False
    cfg: bool = False
    packers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    result = 0.0
    for value in range(256):
        count = data.count(value)
        if count:
            p = count / total
            result -= p * math.log2(p)
    return result


def _u16(data, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _cstring(data, offset: int, limit: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    raw = bytes(data[offset:offset + limit])
    end = raw.find(b"\0")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("latin-1")


class _Layout:
    def __init__(self, ranges: list[tuple[int, int, int]]):
        self.ranges = ranges  # (仮想アドレス, 生サイズ, ファイル位置)

    def offset(self, rva: int) -> int | None:
        for virtual, raw_size, raw_pointer in self.ranges:
            if virtual <= rva < virtual + raw_size:
                return raw_pointer + (rva - virtual)
        return None


def parse_pe(data) -> PeInfo | None:
    """bytes または mmap を解析する。PEでなければ None。壊れた部分は errors に残す。"""
    size = len(data)
    if size < 0x40 or bytes(data[:2]) != b"MZ":
        return None
    info = PeInfo()
    try:
        pe_offset = _u32(data, 0x3C)
        if pe_offset + 24 > size or bytes(data[pe_offset:pe_offset + 4]) != b"PE\0\0":
            return None
        coff = pe_offset + 4
        machine = _u16(data, coff)
        info.machine = MACHINES.get(machine, hex(machine))
        section_count = _u16(data, coff + 2)
        info.timestamp = _u32(data, coff + 4)
        optional_size = _u16(data, coff + 16)
        info.is_dll = bool(_u16(data, coff + 18) & 0x2000)
        optional = coff + 20
        magic = _u16(data, optional)
        if magic not in (0x10B, 0x20B):
            info.errors.append("オプションヘッダーが不正です")
            return info
        info.is_64bit = magic == 0x20B
        entry_rva = _u32(data, optional + 16)
        info.subsystem = SUBSYSTEMS.get(_u16(data, optional + 68), "不明")
        flags = _u16(data, optional + 70)
        info.aslr, info.dep, info.cfg = bool(flags & DLL_ASLR), bool(flags & DLL_DEP), bool(flags & DLL_CFG)
        directories = optional + (112 if info.is_64bit else 96)
        directory_count = _u32(data, directories - 4)

        def directory(index: int) -> tuple[int, int]:
            if index >= directory_count or directories + index * 8 + 8 > size:
                return 0, 0
            return _u32(data, directories + index * 8), _u32(data, directories + index * 8 + 4)

        if section_count > MAX_SECTIONS:
            info.errors.append(f"セクション数が異常です（{section_count}）")
        table = optional + optional_size
        ranges = []
        raw_end = 0
        for index in range(min(section_count, MAX_SECTIONS)):
            entry = table + index * 40
            if entry + 40 > size:
                info.errors.append("セクション表がファイルの外にあります")
                break
            name = bytes(data[entry:entry + 8]).split(b"\0", 1)[0].decode("latin-1")
            virtual_size, virtual = _u32(data, entry + 8), _u32(data, entry + 12)
            raw_size, raw_pointer = _u32(data, entry + 16), _u32(data, entry + 20)
            characteristics = _u32(data, entry + 36)
            usable = max(0, min(raw_size, size - raw_pointer)) if raw_pointer < size else 0
            sample = bytes(data[raw_pointer:raw_pointer + min(usable, ENTROPY_SAMPLE)]) if usable else b""
            info.sections.append(Section(
                name, raw_size, virtual_size, round(entropy(sample), 2),
                bool(characteristics & SCN_EXECUTE), bool(characteristics & SCN_WRITE),
            ))
            packer = PACKER_SECTIONS.get(name.lower())
            if packer and packer not in info.packers:
                info.packers.append(packer)
            if usable:
                ranges.append((virtual, usable, raw_pointer))
                raw_end = max(raw_end, raw_pointer + usable)
            if virtual <= entry_rva < virtual + max(virtual_size, raw_size):
                info.entry_section = name
        info.entry_outside_sections = bool(entry_rva) and info.entry_section is None
        layout = _Layout(ranges)

        # .NET
        info.is_dotnet = directory(14)[0] != 0

        # 署名領域（ここだけ仮想アドレスではなくファイル位置）
        cert_offset, cert_size = directory(4)
        if cert_offset and cert_size:
            info.cert_size = cert_size
            if cert_offset + cert_size > size:
                info.errors.append("署名領域がファイルの外まで続いています")
            else:
                info.cert_slack = _cert_slack(data, cert_offset, cert_size)
        tail = raw_end
        overlay = max(0, size - tail)
        if cert_offset >= tail and cert_size and cert_offset + cert_size <= size:
            overlay = max(0, overlay - cert_size)
        info.overlay_size = overlay

        _read_imports(data, directory(1), layout, info)
    except (struct.error, IndexError, ValueError, OverflowError) as exc:
        info.errors.append(f"解析を途中で打ち切りました（{type(exc).__name__}）")
    return info


def _cert_slack(data, offset: int, size: int) -> int:
    position = 0
    while position + 8 <= size:
        length = _u32(data, offset + position)
        if length < 8 or position + length > size:
            return size - position
        position += (length + 7) & ~7
    return max(0, size - position) if position < size else 0


def _read_imports(data, import_dir: tuple[int, int], layout: _Layout, info: PeInfo) -> None:
    rva, _size = import_dir
    if not rva:
        return
    descriptor = layout.offset(rva)
    if descriptor is None:
        info.errors.append("インポート表を読めません")
        return
    thunk_size = 8 if info.is_64bit else 4
    ordinal_flag = 1 << (thunk_size * 8 - 1)
    total = 0
    for _ in range(MAX_IMPORT_DLLS):
        if descriptor + 20 > len(data):
            return
        original, _stamp, _forwarder, name_rva, first = struct.unpack_from("<IIIII", data, descriptor)
        descriptor += 20
        if not name_rva and not first:
            return
        name_offset = layout.offset(name_rva)
        dll = _cstring(data, name_offset).lower() if name_offset is not None else ""
        if not dll:
            continue
        functions = info.imports.setdefault(dll, [])
        thunk = layout.offset(original or first)
        while thunk is not None and thunk + thunk_size <= len(data) and total < MAX_IMPORT_FUNCS:
            value = _u64(data, thunk) if info.is_64bit else _u32(data, thunk)
            thunk += thunk_size
            if not value:
                break
            total += 1
            if value & ordinal_flag:
                functions.append(f"#{value & 0xFFFF}")
                continue
            hint = layout.offset(value & 0x7FFFFFFF)
            if hint is not None:
                functions.append(_cstring(data, hint + 2))
        info.import_count = total
    info.errors.append("インポート表のDLL数が異常です")


def parse_pe_file(path: str) -> PeInfo | None:
    """ファイルを読み取り専用で解析する。読めない・PEでないときは None。"""
    try:
        with open(path, "rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as view:
                return parse_pe(view)
    except (OSError, ValueError):
        return None
