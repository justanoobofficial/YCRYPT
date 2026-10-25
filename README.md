# YCRYPT

**Offline file encryption for people who like their tools quiet, deliberate, and local.**

YCRYPT is a small desktop app with a dark terminal-inspired interface. It encrypts one file at a time using password-derived keys and authenticated encryption. It does not upload files, phone home, or store your password.

## Features

- AES-256-GCM authenticated encryption
- Scrypt password-based key derivation with a fresh random salt
- Random nonce prefix and unique per-chunk nonces
- Chunked processing to avoid loading the entire file into RAM
- Encrypted original filename metadata
- Decrypt to a new output file; refuses to overwrite an existing file
- Verify an encrypted file by decrypting it to a temporary file and checking authentication
- No accounts, cloud, telemetry, or background service
- Source code for Windows and Linux; GUI requires Tk support

## Security notes

- **If you forget the password, YCRYPT cannot recover your files.** Keep a safe backup of the password.
- Encryption is not a backup. Keep a separate copy of important originals until you have tested decryption.
- This is an early project, not an independently audited security product. Test it with copies of unimportant files first.
- This is for individual files, not whole-disk encryption or secure deletion.
- The output contains a public header (format version, salt, nonce prefix, and chunk size). The original filename is encrypted.
- Use a strong, unique passphrase. Never share it with the encrypted file.

## Requirements

- Python 3.10 or newer
- `cryptography` package
- Tkinter for the desktop interface (`python3-tk` on some Linux distributions)

## Install and run — Windows

1. Install Python from https://www.python.org/downloads/windows/ and enable **Add python.exe to PATH** if offered.
2. Extract/download this repository.
3. Open a terminal in the project folder and run:

```bat
python -m pip install -r requirements.txt
python run_ycrypt.py
```

Or double-click `INSTALL-WINDOWS.bat`.

## Install and run — Linux

Install Python, pip, venv, and Tkinter using your distribution's package manager. On Ubuntu/Debian, for example:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-tk
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run_ycrypt.py
```

## Optional Windows executable

```bat
python -m pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name YCRYPT run_ycrypt.py
```

The executable will be in `dist/YCRYPT.exe`. This packaging command has not been validated on every system. Test with copies of files first.

## Usage

- **Encrypt:** choose a file, choose an output path ending in `.ycrypt`, enter and confirm a passphrase, then encrypt.
- **Decrypt:** select a `.ycrypt` file, choose an output path, enter the passphrase, then decrypt.
- **Verify:** select a `.ycrypt` file and enter the passphrase. YCRYPT checks authentication by decrypting to a temporary file, then deletes it.
- The source file is left untouched by the encryption workflow.

## File format overview

The binary format is versioned and uses an 8-byte magic marker, 16-byte random salt, 8-byte nonce prefix, 4-byte chunk size, and length-prefixed AES-GCM encrypted chunks. Each chunk uses a unique 32-bit counter appended to the random nonce prefix. A final encrypted metadata chunk stores the original filename and plaintext size. Truncation, reordering, and tampering should cause authentication/decryption to fail.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
YCRYPT/
├── run_ycrypt.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── LICENSE
├── tests/test_crypto.py
└── ycrypt/
    ├── __init__.py
    ├── crypto.py
    └── app.py
```

## Roadmap

- Signed, reproducible release builds
- File hashing / manifest export
- Independent security review before recommending use for sensitive or irreplaceable data

## License

MIT — see `LICENSE`.
