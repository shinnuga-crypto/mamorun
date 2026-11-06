"""デジタル署名の詳細を読む。失効確認のための通信はしない（キャッシュのみ）。"""
from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .winapi import (
    _VERIFY_V2, GUID, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, wintrust,
)

crypt32 = ctypes.WinDLL("crypt32")

WTD_CHOICE_CATALOG = 2
CERT_NAME_ATTR_TYPE = 3
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 1
OID_ORGANIZATION = b"2.5.4.10"
FILETIME_UNIX_EPOCH = 116444736000000000

VALID = "valid"
UNSIGNED = "unsigned"
TAMPERED = "tampered"
REVOKED = "revoked"
EXPIRED = "expired"
UNTRUSTED = "untrusted"
DISTRUSTED = "distrusted"
ERROR = "error"
STATUS_LABEL = {
    VALID: "有効", UNSIGNED: "署名なし", TAMPERED: "改ざんの疑い（ハッシュ不一致）", REVOKED: "証明書が失効",
    EXPIRED: "証明書の期限切れ（タイムスタンプなし）", UNTRUSTED: "信頼されていない発行元", DISTRUSTED: "明示的に拒否された証明書",
    ERROR: "検証エラー",
}
_STATUS_BY_CODE = {
    0: VALID,
    0x800B0100: UNSIGNED,  # TRUST_E_NOSIGNATURE
    0x800B0003: UNSIGNED,  # TRUST_E_SUBJECT_FORM_UNKNOWN
    0x800B0001: UNSIGNED,  # TRUST_E_PROVIDER_UNKNOWN
    0x80096010: TAMPERED,  # TRUST_E_BAD_DIGEST
    0x80096004: TAMPERED,  # TRUST_E_CERT_SIGNATURE
    0x800B010C: REVOKED,  # CERT_E_REVOKED
    0x800B0101: EXPIRED,  # CERT_E_EXPIRED
    0x800B0109: UNTRUSTED,  # CERT_E_UNTRUSTEDROOT
    0x800B010A: UNTRUSTED,  # CERT_E_CHAINING
    0x800B0004: DISTRUSTED,  # TRUST_E_SUBJECT_NOT_TRUSTED
    0x800B0111: DISTRUSTED,  # TRUST_E_EXPLICIT_DISTRUST
}
_DIGESTS = {
    "1.3.14.3.2.26": "SHA-1", "1.2.840.113549.2.5": "MD5", "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
}


@dataclass
class CertInfo:
    subject: str = ""
    organization: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha256: str = ""
    sha1: str = ""


@dataclass
class SignatureInfo:
    status: str = UNSIGNED
    kind: str = "なし"  # 埋め込み / カタログ / なし
    code: int = 0
    catalog: str = ""
    digest: str = ""
    signed_at: datetime | None = None  # タイムスタンプ。なければ None
    timestamp_signer: str = ""
    chain: list[CertInfo] = field(default_factory=list)  # 先頭が署名者、末尾がルート

    @property
    def signer(self) -> CertInfo | None:
        return self.chain[0] if self.chain else None

    @property
    def self_signed(self) -> bool:
        return len(self.chain) == 1 and self.chain[0].subject == self.chain[0].issuer


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class _Algorithm(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", _Blob)]


class _CertInfoStruct(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD), ("SerialNumber", _Blob), ("SignatureAlgorithm", _Algorithm),
        ("Issuer", _Blob), ("NotBefore", wintypes.FILETIME), ("NotAfter", wintypes.FILETIME),
    ]


class _CertContext(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD), ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD), ("pCertInfo", ctypes.POINTER(_CertInfoStruct)), ("hCertStore", ctypes.c_void_p),
    ]


class _ProviderCert(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.POINTER(_CertContext))]


class _SignerInfo(ctypes.Structure):
    _fields_ = [("dwVersion", wintypes.DWORD), ("Issuer", _Blob), ("SerialNumber", _Blob), ("HashAlgorithm", _Algorithm)]


class _ProviderSigner(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", wintypes.FILETIME), ("csCertChain", wintypes.DWORD),
        ("pasCertChain", ctypes.c_void_p), ("dwSignerType", wintypes.DWORD), ("psSigner", ctypes.POINTER(_SignerInfo)),
        ("dwError", wintypes.DWORD), ("csCounterSigners", wintypes.DWORD), ("pasCounterSigners", ctypes.c_void_p),
    ]


class _WintrustCatalogInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD), ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR), ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)), ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", ctypes.c_void_p),
    ]


class _CatalogInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(_ProviderSigner)
wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.POINTER(_ProviderSigner), wintypes.DWORD]
wintrust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(_ProviderCert)
wintrust.CryptCATAdminAcquireContext2.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(GUID), wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD,
]
wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
    ctypes.c_void_p, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD,
]
wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
]
wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
wintrust.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(_CatalogInfo), wintypes.DWORD]
wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
crypt32.CertGetNameStringW.argtypes = [
    ctypes.POINTER(_CertContext), wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD,
]
crypt32.CertGetNameStringW.restype = wintypes.DWORD


def filetime_to_datetime(value: wintypes.FILETIME) -> datetime | None:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    if not ticks:
        return None
    try:
        return datetime.fromtimestamp((ticks - FILETIME_UNIX_EPOCH) / 10_000_000, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _cert_name(cert, kind: int, flags: int = 0, param=None) -> str:
    buffer = ctypes.create_unicode_buffer(512)
    crypt32.CertGetNameStringW(cert, kind, flags, param, buffer, len(buffer))
    return buffer.value


def _read_cert(cert) -> CertInfo:
    context = cert.contents
    encoded = ctypes.string_at(context.pbCertEncoded, context.cbCertEncoded)
    details = context.pCertInfo.contents
    serial = ctypes.string_at(details.SerialNumber.pbData, details.SerialNumber.cbData)
    organization = ctypes.create_string_buffer(OID_ORGANIZATION)
    return CertInfo(
        subject=_cert_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE),
        organization=_cert_name(cert, CERT_NAME_ATTR_TYPE, 0, organization),
        issuer=_cert_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG),
        serial=serial[::-1].hex(),  # 内部はリトルエンディアン
        not_before=filetime_to_datetime(details.NotBefore),
        not_after=filetime_to_datetime(details.NotAfter),
        sha256=hashlib.sha256(encoded).hexdigest(),
        sha1=hashlib.sha1(encoded, usedforsecurity=False).hexdigest(),
    )


def _read_chain(signer) -> list[CertInfo]:
    chain = []
    for index in range(min(signer.contents.csCertChain, 16)):
        provider_cert = wintrust.WTHelperGetProvCertFromChain(signer, index)
        if not provider_cert or not provider_cert.contents.pCert:
            break
        chain.append(_read_cert(provider_cert.contents.pCert))
    return chain


def _read_state(data: WINTRUST_DATA, info: SignatureInfo) -> None:
    provider = wintrust.WTHelperProvDataFromStateData(data.hWVTStateData)
    if not provider:
        return
    signer = wintrust.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
    if not signer:
        return
    info.chain = _read_chain(signer)
    if signer.contents.psSigner:
        oid = signer.contents.psSigner.contents.HashAlgorithm.pszObjId
        if oid:
            text = oid.decode("ascii", "replace")
            info.digest = _DIGESTS.get(text, text)
    counter = wintrust.WTHelperGetProvSignerFromChain(provider, 0, True, 0)
    if counter:
        info.signed_at = filetime_to_datetime(counter.contents.sftVerifyAsOf)
        chain = _read_chain(counter)
        if chain:
            info.timestamp_signer = chain[0].subject


def _verify(data: WINTRUST_DATA, info: SignatureInfo) -> None:
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    result = wintrust.WinVerifyTrust(None, ctypes.byref(_VERIFY_V2), ctypes.byref(data))
    info.code = result & 0xFFFFFFFF
    info.status = _STATUS_BY_CODE.get(info.code, ERROR)
    try:
        if info.status != UNSIGNED and data.hWVTStateData:
            _read_state(data, info)
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(_VERIFY_V2), ctypes.byref(data))


def _check_catalog(path: str, info: SignatureInfo) -> None:
    """Windows標準のファイルなどは、ファイル自体でなくカタログで署名されている。"""
    try:
        handle_file = open(path, "rb")
    except OSError:
        return
    with handle_file:
        file_handle = msvcrt.get_osfhandle(handle_file.fileno())
        for algorithm in ("SHA256", None):
            admin = ctypes.c_void_p()
            if not wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
                continue
            try:
                size = wintypes.DWORD(0)
                wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, file_handle, ctypes.byref(size), None, 0)
                if not size.value:
                    continue
                digest = (ctypes.c_ubyte * size.value)()
                if not wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, file_handle, ctypes.byref(size), digest, 0):
                    continue
                catalog = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size.value, 0, None)
                if not catalog:
                    continue
                try:
                    catalog_info = _CatalogInfo()
                    catalog_info.cbStruct = ctypes.sizeof(_CatalogInfo)
                    if not wintrust.CryptCATCatalogInfoFromContext(catalog, ctypes.byref(catalog_info), 0):
                        continue
                    member = _WintrustCatalogInfo()
                    member.cbStruct = ctypes.sizeof(_WintrustCatalogInfo)
                    member.pcwszCatalogFilePath = catalog_info.wszCatalogFile
                    member.pcwszMemberTag = bytes(digest).hex().upper()
                    member.pcwszMemberFilePath = path
                    member.hMemberFile = file_handle
                    member.pbCalculatedFileHash = digest
                    member.cbCalculatedFileHash = size.value
                    member.hCatAdmin = admin
                    data = WINTRUST_DATA()
                    data.dwUnionChoice = WTD_CHOICE_CATALOG
                    data.pFile = ctypes.cast(ctypes.pointer(member), ctypes.POINTER(WINTRUST_FILE_INFO))
                    _verify(data, info)
                    info.kind = "カタログ"
                    info.catalog = catalog_info.wszCatalogFile
                    return
                finally:
                    wintrust.CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
            finally:
                wintrust.CryptCATAdminReleaseContext(admin, 0)


def read_signature(path: str | None) -> SignatureInfo:
    info = SignatureInfo()
    if not path or not os.path.exists(path):
        info.status = ERROR
        return info
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    data = WINTRUST_DATA()
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    _verify(data, info)
    if info.status == UNSIGNED:
        _check_catalog(path, info)
    else:
        info.kind = "埋め込み"
    return info
