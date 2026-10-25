"""YCRYPT's authenticated, chunked file format.

Format v1 is intentionally small and self-contained. This project is early-stage
software; do not use it as the only protection for irreplaceable files.
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"YCRYPT01"
SALT_LEN = 16
NONCE_PREFIX_LEN = 8
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_PREFIX_LEN + 4
CHUNK_SIZE = 1024 * 1024
TAG_LEN = 16
META_MARKER = b"\x01"
DATA_MARKER = b"\x00"
MAX_CHUNKS = (2**32) - 1


class YcryptError(Exception):
    """Expected, user-facing encryption/decryption error."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise YcryptError("Passphrase cannot be empty.")
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def _nonce(prefix: bytes, counter: int) -> bytes:
    if counter >= MAX_CHUNKS:
        raise YcryptError("File has too many chunks for this format version.")
    return prefix + struct.pack(">I", counter)


def _aad(counter: int) -> bytes:
    return MAGIC + struct.pack(">I", counter)


def _write_record(stream, payload: bytes) -> None:
    stream.write(struct.pack(">I", len(payload)))
    stream.write(payload)


def _read_exact(stream, count: int) -> bytes:
    data = stream.read(count)
    if len(data) != count:
        raise YcryptError("Encrypted file is incomplete or damaged.")
    return data


def _read_record(stream) -> bytes | None:
    raw_len = stream.read(4)
    if not raw_len:
        return None
    if len(raw_len) != 4:
        raise YcryptError("Encrypted file is incomplete or damaged.")
    length = struct.unpack(">I", raw_len)[0]
    if length < TAG_LEN + 1 or length > CHUNK_SIZE + 65536 + TAG_LEN + 1:
        raise YcryptError("Encrypted file has an invalid record length.")
    return _read_exact(stream, length)


def encrypt_file(source: Path, destination: Path, password: str,
                 progress: Callable[[int], None] | None = None) -> None:
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise YcryptError("Choose an existing file.")
    if source.resolve() == destination.resolve():
        raise YcryptError("Output must be different from the original file.")
    if destination.exists():
        raise YcryptError("The output file already exists. Choose a new name.")

    salt = os.urandom(SALT_LEN)
    prefix = os.urandom(NONCE_PREFIX_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    total = source.stat().st_size
    counter = 0
    done = 0
    destination.parent.mkdir(parents=True, exist_ok=True)

    try:
        with source.open("rb") as inp, destination.open("xb") as out:
            out.write(MAGIC + salt + prefix + struct.pack(">I", CHUNK_SIZE))
            while True:
                chunk = inp.read(CHUNK_SIZE)
                if not chunk:
                    break
                ciphertext = aes.encrypt(_nonce(prefix, counter), DATA_MARKER + chunk, _aad(counter))
                _write_record(out, ciphertext)
                counter += 1
                done += len(chunk)
                if progress:
                    progress(100 if total == 0 else min(99, int(done * 100 / total)))

            meta = json.dumps({
                "marker": "YCRYPT_META_V1",
                "name": source.name,
                "size": total,
                "chunks": counter,
            }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ciphertext = aes.encrypt(_nonce(prefix, counter), META_MARKER + meta, _aad(counter))
            _write_record(out, ciphertext)
            out.flush()
            os.fsync(out.fileno())
        if progress:
            progress(100)
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _decrypt_to_temp(source: Path, password: str, progress=None):
    source = Path(source)
    temp = tempfile.NamedTemporaryFile(prefix="ycrypt-", suffix=".tmp", delete=False)
    temp_path = Path(temp.name)
    try:
        with source.open("rb") as inp, temp:
            header = _read_exact(inp, HEADER_LEN)
            if header[:len(MAGIC)] != MAGIC:
                raise YcryptError("This is not a supported YCRYPT file.")
            pos = len(MAGIC)
            salt = header[pos:pos + SALT_LEN]
            pos += SALT_LEN
            prefix = header[pos:pos + NONCE_PREFIX_LEN]
            pos += NONCE_PREFIX_LEN
            chunk_size = struct.unpack(">I", header[pos:pos + 4])[0]
            if chunk_size != CHUNK_SIZE:
                raise YcryptError("Unsupported chunk size in encrypted file.")

            aes = AESGCM(_derive_key(password, salt))
            counter = 0
            total = 0
            metadata = None
            file_size = max(source.stat().st_size, 1)
            consumed = HEADER_LEN
            while True:
                record = _read_record(inp)
                if record is None:
                    break
                try:
                    plain = aes.decrypt(_nonce(prefix, counter), record, _aad(counter))
                except InvalidTag as exc:
                    raise YcryptError("Wrong passphrase or the file has been altered.") from exc
                consumed += 4 + len(record)
                counter += 1
                if plain.startswith(DATA_MARKER):
                    if metadata is not None:
                        raise YcryptError("Invalid file structure.")
                    data = plain[1:]
                    temp.write(data)
                    total += len(data)
                elif plain.startswith(META_MARKER):
                    if metadata is not None:
                        raise YcryptError("Invalid file structure.")
                    try:
                        metadata = json.loads(plain[1:].decode("utf-8"))
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise YcryptError("Encrypted metadata is invalid.") from exc
                    if metadata.get("marker") != "YCRYPT_META_V1":
                        raise YcryptError("Encrypted metadata is invalid.")
                    if inp.read(1):
                        raise YcryptError("Data found after the metadata record.")
                    break
                else:
                    raise YcryptError("Encrypted file contains an unknown record type.")
                if progress:
                    progress(min(99, int(consumed * 100 / file_size)))

            if metadata is None:
                raise YcryptError("Encrypted file is incomplete: metadata is missing.")
            if metadata.get("chunks") != counter - 1 or metadata.get("size") != total:
                raise YcryptError("File integrity check failed.")
            name = metadata.get("name")
            if not isinstance(name, str) or not name or Path(name).name != name:
                raise YcryptError("Encrypted filename metadata is invalid.")
            temp.flush()
            os.fsync(temp.fileno())
        if progress:
            progress(100)
        return temp_path, metadata
    except Exception:
        try:
            temp.close()
        except Exception:
            pass
        temp_path.unlink(missing_ok=True)
        raise


def decrypt_file(source: Path, destination: Path, password: str,
                 progress: Callable[[int], None] | None = None) -> None:
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise YcryptError("Output must be different from the encrypted file.")
    if destination.exists():
        raise YcryptError("The output file already exists. Choose a new name.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        temp_path, _meta = _decrypt_to_temp(source, password, progress)
        with destination.open("xb") as out, temp_path.open("rb") as inp:
            while True:
                block = inp.read(CHUNK_SIZE)
                if not block:
                    break
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


def verify_file(source: Path, password: str,
                progress: Callable[[int], None] | None = None) -> dict:
    """Authenticate the complete file by decrypting to a temporary file."""
    temp_path = None
    try:
        temp_path, metadata = _decrypt_to_temp(Path(source), password, progress)
        return metadata
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)
