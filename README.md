# Chrome App-Bound Encryption Offline Decryption

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/target-Windows%20(offline)-lightgrey)
![Status](https://img.shields.io/badge/status-research%2Flab-orange)

Offline decryption of Chrome-stored **Login Data**, **Cookies** and **Web Data** (credit cards, CVC, IBANs), covering both legacy DPAPI encryption (**v10**) and Chrome's **App-Bound Encryption (ABE / v20)**.

Everything runs offline against copied artifacts (`Local State`, `Login Data`, `Cookies`, `Web Data`, DPAPI masterkeys, SYSTEM DPAPI/KSP material) — no interaction with a live Chrome process is required.

> [!WARNING]
> For educational and research purposes only. Use only on systems you own or have explicit permission to examine. Provided as-is, with no warranties of any kind.

This tool is the practical companion to my technical deep dive into Chrome's offline decryption chain (DPAPI v10 and App-Bound Encryption v20): [From the Login Screen to Full Compromise → §4 Offline Chrome Credentials Decryption](https://0rcruxe.github.io/posts/from-the-login-screen-to-full-compromise/#4-offline-chrome-credentials-decryption).

---

## Features

- **v10 (DPAPI) decryption** — unwraps the AES key from `Local State` using the user's DPAPI masterkey.
- **ABE / v20 (App-Bound) decryption** — full offline chain: SYSTEM DPAPI userkey → SYSTEM masterkey → KSP key blob → `blob1` → `blob2` → key derivation from content flag (1, 2 or 3).
- **Login Data**: site / login / decrypted password.
- **Cookies**: host / name / decrypted value.
- **Web Data**: credit cards, stored CVC, IBANs.
- **`--info` mode**: read-only overview of what encryption version protects each entry, without decrypting anything.
- **Interactive prompts with caching**: file paths, SID, etc. are cached per `Local State` file in `.data.json` so repeated runs don't ask again.
- Prints the derived `browser_key_v10` / `browser_key_v20` in hex at the end of a `--decrypt` run.

## Requirements

- Python 3.10+
- Dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Usage

### Inspect only (no decryption)

```bash
python3 chrome_abe_offline_decrypt.py --info -s "Local State" -l "Login Data" -c "Cookies" -w "Web Data"
```

### Decrypt

```bash
python3 chrome_abe_offline_decrypt.py --decrypt -s "Local State" -l "Login Data" -c "Cookies" -w "Web Data"
```

You'll be prompted interactively for whatever the encryption chain requires:

- **v10**: masterkey file, account SID, password.
- **ABE / v20** (only if App-Bound keys are present in `Local State`): SYSTEM DPAPI userkey, SYSTEM DPAPI key file, KSP key file, then the account SID/masterkey/password again for `blob2`.

### CLI options

| Flag | Description |
|---|---|
| `-s`, `--localstate` | Path to Chrome's `Local State` JSON file |
| `-l`, `--logindata` | Path to Chrome's `Login Data` SQLite database |
| `-c`, `--cookies` | Path to Chrome's `Cookies` SQLite database |
| `-w`, `--webdata` | Path to Chrome's `Web Data` SQLite database |
| `--info` | Show encryption metadata only, no decryption |
| `--decrypt` | Decrypt the requested databases |
| `-v`, `--verbose` | Verbose logging (key sizes, decryption steps), optional for both `--info` and `--decrypt` |
