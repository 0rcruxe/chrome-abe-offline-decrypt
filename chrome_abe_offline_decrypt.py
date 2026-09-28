#!/usr/bin/env python3
"""Inspect and decrypt Chrome-stored credentials, cookies, and web data."""

import argparse
import base64
import getpass
import glob
import hashlib
import json
import os
import readline
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from rich.table import Table
from rich.console import Console
from rich.markup import escape as rich_escape
from tabulate import tabulate
from dpapick3 import blob as dpapi_blob_mod
from dpapick3 import masterkey as dpapi_mk_mod
from Crypto.Cipher import AES, ChaCha20_Poly1305

# Encryption version identification

def get_encryption_version(encrypted_value: bytes) -> str:
    if not encrypted_value:
        return "plaintext"
    prefix = encrypted_value[:3]
    try:
        tag = prefix.decode("ascii")
        if tag.startswith("v") and tag[1:].isdigit():
            labels = {
                "v10": "v10 (DPAPI/AES-GCM)",
                "v11": "v11 (AES-GCM)",
                "v20": "v20 (App-Bound AES-GCM)",
            }
            return labels.get(tag, tag)
    except Exception:
        pass
    return "DPAPI (legacy)"

# Table output (rich, falling back to tabulate)

def print_table(headers: list, rows: list, title: str = "") -> None:
    console = Console()
    table = Table(title=title, show_header=True, header_style="bold green")
    for h in headers:
        table.add_column(h, overflow="fold")
    for row in rows:
        table.add_row(*[rich_escape(str(c)) for c in row])
    console.print(table)
    return

    if title:
        print(f"\n{title}")
    print(tabulate(rows, headers=headers))
    return


# SQLite helpers

def open_sqlite_copy(path: str):
    """Duplicate the database to a temp file (Chrome can keep it locked) and open the copy."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    shutil.copy2(path, tmp.name)
    return sqlite3.connect(tmp.name), tmp.name

# Interactive prompts (readline) with .data.json caching

DATA_PATH = ".data.json"


def _load_data() -> list:
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_data(entries: list) -> None:
    with open(DATA_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def _get_state_cache(entries: list, state_path: str) -> dict:
    """Fetch (or create) the cached-paths entry for this Local State file."""
    norm = os.path.normpath(state_path)
    for entry in entries:
        if os.path.normpath(entry.get("state", "")) == norm:
            return entry["paths"]
    new_entry: dict = {"state": state_path, "paths": {}}
    entries.append(new_entry)
    return new_entry["paths"]


def _prompt_text(label: str, key: str, data_cache: dict, completions: list | None = None) -> str:
    """Ask for input with readline pre-fill and optional tab-completion."""
    cached = data_cache.get(key, "")

    if completions is not None:
        def _completer(text, state):
            matches = [c for c in completions if c.lower().startswith(text.lower())]
            return matches[state] if state < len(matches) else None
        readline.set_completer(_completer)
    else:
        def _completer(text, state):
            matches = glob.glob(text + "*")
            return matches[state] if state < len(matches) else None
        readline.set_completer(_completer)

    readline.parse_and_bind("tab: complete")
    if cached:
        readline.set_startup_hook(lambda: readline.insert_text(cached))

    try:
        value = input(f"{label}: ").strip()
    finally:
        readline.set_startup_hook(None)
        readline.set_completer(None)

    value = value or cached
    if value:
        data_cache[key] = value
    return value


def _prompt_secret(label: str, key: str, data_cache: dict) -> str:
    """Ask for a secret; any cached value is hinted, never pre-filled."""
    cached = data_cache.get(key, "")
    hint = " [cached, press Enter to reuse]" if cached else ""
    value = getpass.getpass(f"{label}{hint}: ")
    value = value or cached
    if value:
        data_cache[key] = value
    return value


def _read_bytes_input(val: str) -> bytes:
    """Accept a file path (read as binary) or a raw hex string."""
    p = Path(val)
    if p.exists():
        return p.read_bytes()
    try:
        return bytes.fromhex(val.strip())
    except ValueError:
        raise ValueError(f"Cannot read '{val}' as a file path or a hex string")


# KSP auto-detection

def find_ksp_key(ksp_dir: str, sys_mk_guid: str) -> str | None:
    """Scan a directory of KSP key files and return the one whose
    embedded DPAPI blob requires the given SYSTEM masterkey GUID."""
    DPAPI_MAGIC = bytes([0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF])
    for fname in os.listdir(ksp_dir):
        fpath = os.path.join(ksp_dir, fname)
        try:
            raw = Path(fpath).read_bytes()
            boffset = raw[::-1].index(DPAPI_MAGIC[::-1]) + len(DPAPI_MAGIC)
            blob = dpapi_blob_mod.DPAPIBlob(raw[-boffset:])
            if str(blob.mkguid).lower() == sys_mk_guid.lower():
                return fpath
        except Exception:
            continue
    return None


# ChromeDecryptor

class ChromeDecryptor:
    def __init__(self, localstate_path: str | None = None, verbose: bool = False):
        self.localstate_path = localstate_path
        self.verbose = verbose
        self.browserkey_v10: bytes | None = None
        self.browserkey_v20: bytes | None = None
        self._user_masterkey_v10: bytes | None = None  # masterkey for encrypted_key (v10)
        self._v20_key_attempted: bool = False

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    # v10 key loading

    def load_key_localstate(self) -> None:
        """Extract the DPAPI-wrapped AES key from Local State and unwrap it (v10)."""
        if not self.localstate_path:
            raise ValueError("--localstate is required for --decrypt")

        with open(self.localstate_path, "r", encoding="utf-8") as f:
            state = json.load(f)

        encrypted_key_b64 = state.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            raise ValueError("os_crypt.encrypted_key missing from Local State")

        # Chrome format: base64("DPAPI" + <raw DPAPI blob>)
        raw_with_prefix = base64.b64decode(encrypted_key_b64)
        if raw_with_prefix[:5] != b"DPAPI":
            raise ValueError("Unexpected encrypted_key layout (no DPAPI prefix)")
        raw_blob = raw_with_prefix[5:]

        dpapi_blob = dpapi_blob_mod.DPAPIBlob(raw_blob)
        mk_guid = str(dpapi_blob.mkguid)
        self._log(f"[*] v10 user masterkey GUID needed: {mk_guid}")

        entries = _load_data()
        data_cache = _get_state_cache(entries, self.localstate_path)

        mk_path = _prompt_text(
            f"  v10 user masterkey file (GUID={mk_guid})",
            "mk_path_v10",
            data_cache,
        )
        sid = _prompt_text(
            "  Account SID",
            "sid",
            data_cache,
            completions=[data_cache["sid"]] if "sid" in data_cache else [],
        )
        password = _prompt_secret("  Account password", "password", data_cache)

        _save_data(entries)

        with open(mk_path, "rb") as _f:
            mkf = dpapi_mk_mod.MasterKeyFile(_f.read())
        mkf.decryptWithPassword(sid, password)
        if not mkf.decrypted:
            raise ValueError("Could not decrypt the v10 user masterkey - check the SID/password")

        self._user_masterkey_v10 = mkf.get_key()
        dpapi_blob.decrypt(self._user_masterkey_v10)
        if not dpapi_blob.decrypted:
            raise ValueError("DPAPI blob decryption failed for v10")

        self.browserkey_v10 = dpapi_blob.cleartext
        self._log(f"[+] v10 browser key ready ({len(self.browserkey_v10)} bytes)")

    # v20 App-Bound key loading

    def load_v20_key(self) -> None:
        """Reconstruct the v20 browser key from SYSTEM DPAPI, the KSP blob, and app_bound_encrypted_key."""

        with open(self.localstate_path, "r", encoding="utf-8") as _f:
            state = json.load(_f)
        app_bound_b64 = state.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not app_bound_b64:
            raise ValueError("os_crypt.app_bound_encrypted_key missing from Local State")
        app_bound_raw = base64.b64decode(app_bound_b64)
        if app_bound_raw[:4] != b"APPB":
            raise ValueError("Unexpected app_bound_encrypted_key layout (no APPB prefix)")
        sys_mk_guid = str(dpapi_blob_mod.DPAPIBlob(app_bound_raw[4:]).mkguid)

        entries = _load_data()
        data_cache = _get_state_cache(entries, self.localstate_path)
        print("\n[*] App-Bound (v20) encryption in use - SYSTEM DPAPI inputs needed")

        system_userkey_input = _prompt_text(
            "  SYSTEM DPAPI userkey (path or hex bytes, e.g. from secretsdump)",
            "system_userkey",
            data_cache,
        )
        system_dpapi_key_path = _prompt_text(
            f"  SYSTEM DPAPI key file (GUID={sys_mk_guid})",
            "system_dpapi_key",
            data_cache,
        )

        # KSP: accept a directory (auto-detect) or a direct file path
        ksp_input = _prompt_text(
            "  KSP keys directory or file (format <16hex>_<guid>)",
            "ksp_key",
            data_cache,
        )
        if os.path.isdir(ksp_input):
            match = find_ksp_key(ksp_input, sys_mk_guid)
            if match:
                print(f"  [+] KSP key auto-selected: {os.path.basename(match)}")
                ksp_key_path = match
            else:
                raise ValueError(
                    f"No KSP file in '{ksp_input}' matches SYSTEM masterkey GUID {sys_mk_guid}"
                )
        else:
            ksp_key_path = ksp_input

        _save_data(entries)

        # 1. Decrypt the SYSTEM masterkey using the DPAPI userkey
        system_userkey = _read_bytes_input(system_userkey_input)
        with open(system_dpapi_key_path, "rb") as _f:
            sys_mkf = dpapi_mk_mod.MasterKeyFile(_f.read())
        sys_mkf.decryptWithKey(system_userkey)
        if not sys_mkf.decrypted:
            raise ValueError("Could not decrypt the SYSTEM masterkey with the given userkey")
        system_masterkey = sys_mkf.get_key()
        self._log("[+] SYSTEM masterkey unlocked")

        # 2. Decrypt the KSP key blob (Google Chromekey1)
        ksp_raw = Path(ksp_key_path).read_bytes()
        DPAPI_MAGIC = bytes([0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF])
        boffset = ksp_raw[::-1].index(DPAPI_MAGIC[::-1]) + len(DPAPI_MAGIC)
        ksp_blob = dpapi_blob_mod.DPAPIBlob(ksp_raw[-boffset:])
        ksp_blob.decrypt(system_masterkey, entropy=b"xT5rZW5qVVbrvpuA\x00")
        if not ksp_blob.decrypted:
            raise ValueError("Could not decrypt the KSP DPAPI blob with the SYSTEM masterkey")
        ksp_raw_key = ksp_blob.cleartext
        # BCRYPT_KEY_DATA_BLOB: magic(4b "KDBM") | version(4b) | cbKeyData(4b) | key
        if len(ksp_raw_key) >= 12 and ksp_raw_key[:4] == b"KDBM":
            cb_key = int.from_bytes(ksp_raw_key[8:12], "little")
            ksp_key = ksp_raw_key[12: 12 + cb_key]
        else:
            ksp_key = ksp_raw_key[:32]
        self._log(f"[+] KSP key recovered ({len(ksp_key)} bytes, from a {len(ksp_raw_key)}-byte blob)")

        # 3. Decrypt blob1 (SYSTEM key) -> reveals blob2
        blob1 = dpapi_blob_mod.DPAPIBlob(app_bound_raw[4:])
        blob1.decrypt(system_masterkey)
        if not blob1.decrypted:
            raise ValueError("Could not decrypt app_bound blob1 with the SYSTEM DPAPI key")

        blob2_probe = dpapi_blob_mod.DPAPIBlob(blob1.cleartext)
        needed_guid = str(blob2_probe.mkguid)
        self._log(f"[*] blob2 needs user masterkey GUID: {needed_guid}")

        sid2 = _prompt_text(
            "  Account SID (blob2 masterkey)",
            "sid",
            data_cache,
        )
        mk2_path = _prompt_text(
            f"  blob2 masterkey file (GUID={needed_guid})",
            "mk2_path",
            data_cache,
        )
        password2 = _prompt_secret("  Password (blob2 masterkey)", "password", data_cache)
        _save_data(entries)

        with open(mk2_path, "rb") as _f:
            mkf2 = dpapi_mk_mod.MasterKeyFile(_f.read())
        mkf2.decryptWithPassword(sid2, password2)
        if not mkf2.decrypted:
            raise ValueError("Could not decrypt blob2's user masterkey - check the SID/password")

        blob2 = dpapi_blob_mod.DPAPIBlob(blob1.cleartext)
        blob2.decrypt(mkf2.get_key())
        if not blob2.decrypted:
            raise ValueError("Could not decrypt app_bound blob2 with the user DPAPI key")

        # 4. Parse: header_len(4b LE) | header | content_len(4b LE) | content
        data = blob2.cleartext
        header_len = int.from_bytes(data[0:4], "little")
        content_start = 4 + header_len + 4
        content_len = int.from_bytes(data[4 + header_len: content_start], "little")
        content = data[content_start: content_start + content_len]

        # 5. Derive the browser key from the content flag
        self.browserkey_v20 = self._derive_v20_key(content, ksp_key)
        self._log(f"[+] v20 browser key recovered ({len(self.browserkey_v20)} bytes)")

    @staticmethod
    def _derive_v20_key(content: bytes, ksp_key: bytes) -> bytes:
        flag = content[0]

        if flag in (1, 2):
            # flag(1b) | IV(12b) | TAG(16b) | ciphertext
            iv = content[1:13]
            tag = content[13:29]
            ct = content[29:]
            if flag == 1:
                key = bytes.fromhex(
                    "B31C6E241AC846728DA9C1FAC4936651"
                    "CFFB944D143AB816276BCC6DA0284787"
                )
                return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
            else:
                key = bytes.fromhex(
                    "E98F37D7F4E1FA433D19304DC2258042"
                    "090E2D1D7EEA7670D41F738D08729660"
                )
                return ChaCha20_Poly1305.new(key=key, nonce=iv).decrypt_and_verify(ct, tag)

        if flag == 3:
            # flag(1b) | encrypted_aes_key(32b) | IV(12b) | ciphertext(32b) | TAG(16b)
            enc_key = content[1:33]
            iv = content[33:45]
            ct = content[45:77]
            tag = content[77:93]
            xor_key = bytes.fromhex(
                "CCF8A1CEC56605B8517552BA1A2D061C"
                "03A29E90274FB2FCF59BA4B75C392390"
            )
            key1 = AES.new(ksp_key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(enc_key)
            key2 = bytes(a ^ b for a, b in zip(key1, xor_key))
            return AES.new(key2, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)

        raise ValueError(f"Unrecognized app-bound content flag: {flag}")

    # Field decryption

    def decrypt_value(self, encrypted_value: bytes) -> str:
        if not encrypted_value:
            return ""

        prefix = encrypted_value[:3]
        try:
            tag = prefix.decode("ascii")
        except Exception:
            tag = ""

        if tag == "v20":
            if not self._v20_key_attempted and self.browserkey_v20 is None:
                self._v20_key_attempted = True
                try:
                    self.load_v20_key()
                except Exception as exc:
                    print(f"[!] Failed to load the v20 key: {exc}")
            if self.browserkey_v20 is None:
                return "[v20: key not available]"
            try:
                return self._decrypt_aes_gcm(encrypted_value, self.browserkey_v20)
            except Exception as exc:
                return f"[decryption error: {exc}]"

        if tag in ("v10", "v11"):
            if self.browserkey_v10 is None:
                return "[error: browser key not loaded yet]"
            try:
                return self._decrypt_aes_gcm(encrypted_value, self.browserkey_v10)
            except Exception as exc:
                return f"[decryption error: {exc}]"

        return "[unsupported: legacy DPAPI scheme]"

    @staticmethod
    def _decrypt_aes_gcm(encrypted_value: bytes, key: bytes) -> str:
        # Format: version(3b) | IV(12b) | ciphertext | TAG(16b)
        iv = encrypted_value[3:15]
        payload = encrypted_value[15:]
        ciphertext, tag = payload[:-16], payload[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8", errors="replace")

    # Decrypting Login Data / Cookies

    def decrypt_logindata(self, path: str) -> None:
        conn, tmp = open_sqlite_copy(path)
        try:
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = []
            for origin_url, username, enc_pw in cur.fetchall():
                if isinstance(enc_pw, str):
                    enc_pw = enc_pw.encode()
                rows.append((
                    origin_url or "",
                    username or "",
                    self.decrypt_value(enc_pw),
                ))
            print_table(
                ["Site", "Login", "Password"],
                rows,
                title="Decrypted Login Data",
            )
        finally:
            conn.close()
            os.unlink(tmp)

    def decrypt_cookies(self, path: str) -> None:
        conn, tmp = open_sqlite_copy(path)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(cookies)")
            cols = {row[1] for row in cur.fetchall()}
            enc_col = "encrypted_value" if "encrypted_value" in cols else "value"
            host_col = "host_key" if "host_key" in cols else "host"
            cur.execute(f"SELECT {host_col}, name, {enc_col} FROM cookies")
            rows = []
            for host, name, enc_val in cur.fetchall():
                if isinstance(enc_val, str):
                    enc_val = enc_val.encode()
                rows.append((
                    host or "",
                    name or "",
                    self.decrypt_value(enc_val)
                        if enc_val[:3] != b"v20" else
                            self.decrypt_value(enc_val)[32:],
                ))
            print_table(
                ["Site", "Cookie Name", "Value"],
                rows,
                title="Decrypted Cookies",
            )
        finally:
            conn.close()
            os.unlink(tmp)

    # Decrypting Web Data (credit cards, CVC, IBANs)

    def decrypt_webdata(self, path: str) -> None:
        conn, tmp = open_sqlite_copy(path)
        try:
            cur = conn.cursor()

            # -- Credit cards --
            cur.execute(
                "SELECT name_on_card, expiration_month, expiration_year, "
                "card_number_encrypted, nickname FROM credit_cards"
            )
            rows = []
            for name, exp_m, exp_y, enc_num, nickname in cur.fetchall():
                if isinstance(enc_num, str):
                    enc_num = enc_num.encode()
                rows.append((
                    name or "",
                    f"{exp_m or ''}/{exp_y or ''}",
                    nickname or "",
                    self.decrypt_value(enc_num) if enc_num else "",
                ))
            print_table(
                ["Name on card", "Expiration", "Nickname", "Card number"],
                rows,
                title="Decrypted Credit Cards",
            )

            # -- Stored CVC (opt-in feature, table absent on older Chrome) --
            try:
                cur.execute("SELECT guid, value_encrypted FROM local_stored_cvc")
                cvc_rows = []
                for guid, enc_cvc in cur.fetchall():
                    if isinstance(enc_cvc, str):
                        enc_cvc = enc_cvc.encode()
                    cvc_rows.append((guid, self.decrypt_value(enc_cvc) if enc_cvc else ""))
                if cvc_rows:
                    print_table(["Card GUID", "CVC"], cvc_rows, title="Decrypted Stored CVC")
            except sqlite3.OperationalError:
                pass

            # -- IBANs --
            try:
                cur.execute("SELECT nickname, value_encrypted FROM local_ibans")
                iban_rows = []
                for nickname, enc_iban in cur.fetchall():
                    if isinstance(enc_iban, str):
                        enc_iban = enc_iban.encode()
                    iban_rows.append((nickname or "", self.decrypt_value(enc_iban) if enc_iban else ""))
                if iban_rows:
                    print_table(["Nickname", "IBAN"], iban_rows, title="Decrypted IBANs")
            except sqlite3.OperationalError:
                pass

        finally:
            conn.close()
            os.unlink(tmp)


# --info command (read-only inspection, no decryption)

def info_logindata(path: str) -> None:
    conn, tmp = open_sqlite_copy(path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = []
        for origin_url, username, enc_pw in cur.fetchall():
            if isinstance(enc_pw, str):
                enc_pw = enc_pw.encode()
            rows.append((origin_url or "", username or "", get_encryption_version(enc_pw)))
        print_table(["Site", "Login", "Password Encryption"], rows, title="Login Data (overview)")
    finally:
        conn.close()
        os.unlink(tmp)


def info_cookies(path: str) -> None:
    conn, tmp = open_sqlite_copy(path)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(cookies)")
        cols = {row[1] for row in cur.fetchall()}
        enc_col = "encrypted_value" if "encrypted_value" in cols else "value"
        host_col = "host_key" if "host_key" in cols else "host"
        cur.execute(f"SELECT {host_col}, name, {enc_col} FROM cookies")
        rows = []
        for host, name, enc_val in cur.fetchall():
            if isinstance(enc_val, str):
                enc_val = enc_val.encode()
            rows.append((host or "", name or "", get_encryption_version(enc_val)))
        print_table(["Site", "Cookie Name", "Encryption Version"], rows, title="Cookies (overview)")
    finally:
        conn.close()
        os.unlink(tmp)


def info_webdata(path: str) -> None:
    conn, tmp = open_sqlite_copy(path)
    try:
        cur = conn.cursor()

        # Card numbers
        cur.execute("SELECT name_on_card, card_number_encrypted FROM credit_cards")
        rows = []
        for name, enc_num in cur.fetchall():
            if isinstance(enc_num, str):
                enc_num = enc_num.encode()
            rows.append((name or "", get_encryption_version(enc_num)))
        print_table(["Name on card", "Encryption"], rows, title="Web Data: Credit Cards")

        # Stored CVC (table absent on older Chrome versions)
        try:
            cur.execute("SELECT guid, value_encrypted FROM local_stored_cvc")
            cvc_rows = []
            for guid, enc_cvc in cur.fetchall():
                if isinstance(enc_cvc, str):
                    enc_cvc = enc_cvc.encode()
                cvc_rows.append((guid, get_encryption_version(enc_cvc)))
            if cvc_rows:
                print_table(["Card GUID", "Encryption"], cvc_rows, title="Web Data: Stored CVC")
        except sqlite3.OperationalError:
            pass

        # IBANs
        try:
            cur.execute("SELECT nickname, value_encrypted FROM local_ibans")
            iban_rows = []
            for nickname, enc_iban in cur.fetchall():
                if isinstance(enc_iban, str):
                    enc_iban = enc_iban.encode()
                iban_rows.append((nickname or "", get_encryption_version(enc_iban)))
            if iban_rows:
                print_table(["Nickname", "Encryption"], iban_rows, title="Web Data: IBANs")
        except sqlite3.OperationalError:
            pass

    finally:
        conn.close()
        os.unlink(tmp)


def info_localstate(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        state = json.load(f)

    os_crypt = state.get("os_crypt", {})
    rows = []

    encrypted_key = os_crypt.get("encrypted_key")
    if encrypted_key:
        key_bytes = base64.b64decode(encrypted_key)
        source = "DPAPI-wrapped AES key" if key_bytes[:5] == b"DPAPI" else "unrecognized wrapping"
        rows.append(("os_crypt.encrypted_key", source, base64.b64encode(key_bytes).decode()))

    app_bound_key = os_crypt.get("app_bound_encrypted_key")
    if app_bound_key:
        rows.append(("os_crypt.app_bound_encrypted_key", "App-Bound AES key", app_bound_key))

    if rows:
        print_table(["Field", "Type", "Value (base64)"], rows, title="Local State: Key Material")
    else:
        print("No encrypted key material present in Local State.")


def cmd_info(args: argparse.Namespace) -> None:
    if not any([args.logindata, args.cookies, args.localstate, args.webdata]):
        print("--info needs at least one of --logindata, --cookies, --localstate, --webdata.")
        sys.exit(1)
    if args.logindata:
        info_logindata(args.logindata)
    if args.cookies:
        info_cookies(args.cookies)
    if args.webdata:
        info_webdata(args.webdata)
    if args.localstate:
        info_localstate(args.localstate)


# --decrypt command

def cmd_decrypt(args: argparse.Namespace) -> None:
    if not args.localstate:
        print("--decrypt needs --localstate to load the browser AES key.")
        sys.exit(1)
    if not args.logindata and not args.cookies and not args.webdata:
        print("--decrypt needs --logindata, --cookies, and/or --webdata.")
        sys.exit(1)

    decryptor = ChromeDecryptor(localstate_path=args.localstate, verbose=args.verbose)
    decryptor.load_key_localstate()

    if args.logindata:
        decryptor.decrypt_logindata(args.logindata)
    if args.cookies:
        decryptor.decrypt_cookies(args.cookies)
    if args.webdata:
        decryptor.decrypt_webdata(args.webdata)

    print()
    if decryptor.browserkey_v10:
        print(f"[+] browser_key_v10 ({len(decryptor.browserkey_v10)}-byte hex): "
              f"{decryptor.browserkey_v10.hex()}")
    if decryptor.browserkey_v20:
        print(f"[+] browser_key_v20 ({len(decryptor.browserkey_v20)}-byte hex): "
              f"{decryptor.browserkey_v20.hex()}")



# CLI parser and entry point

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chrome-decrypt",
        description="Inspect and decrypt Chrome credentials, cookies, web data and related key material.",
    )
    parser.add_argument(
        "-l", "--logindata",
        metavar="PATH",
        help='Path to Chrome\'s "Login Data" SQLite database',
    )
    parser.add_argument(
        "-s", "--localstate",
        metavar="PATH",
        help='Path to Chrome\'s "Local State" JSON file',
    )
    parser.add_argument(
        "-c", "--cookies",
        metavar="PATH",
        help="Path to Chrome's Cookies SQLite database",
    )
    parser.add_argument(
        "-w", "--webdata",
        metavar="PATH",
        help='Path to Chrome\'s "Web Data" SQLite database (cards, CVC, IBANs)',
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Display encryption metadata (versions, key material) without decrypting anything",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help=(
            "Decrypt passwords, cookies and/or web data. "
            "Requires --localstate plus at least one of --logindata, --cookies, --webdata. "
            "Interactively asks for the DPAPI masterkey paths, SID, and password, caching answers in .data.json. "
            "Prints the resulting browser_key_v10/v20 hex at the end."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (key sizes, decryption steps)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.info:
        cmd_info(args)
        return

    if args.decrypt:
        cmd_decrypt(args)
        return

    print("No action selected - use --info or --decrypt (see --help for usage).")


if __name__ == "__main__":
    main()
