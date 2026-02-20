# Ankama Launcher Emulator

A tool that emulates the Ankama Launcher to launch **Dofus 3** directly — without needing the official launcher running. Supports multi-account management, per-account SOCKS5 proxies, and network interface selection, all from a simple web UI.

---

## How it works

The official Ankama Launcher stores your credentials encrypted in `%APPDATA%\zaap\`. This tool:

1. Reads and decrypts those stored API keys using your machine's UUID
2. Starts a local Thrift server on port `26116` (the same port the game expects from the launcher)
3. Intercepts the game's connection via a transparent proxy (mitmproxy)
4. Launches `Dofus.exe` with the correct arguments so it connects to the local emulated launcher instead of Zaap

You must have logged in at least once through the official Ankama Launcher so that your credentials are stored locally.

---

## Requirements

- **Dofus 3** installed via the official Ankama Launcher (at least one account logged in)
- **Python >= 3.12**
- **uv** — fast Python package manager

Install uv:
```bash
pip install uv
```

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Valentin-alix/AnkamaLauncherEmulatorProxy
cd AnkamaLauncherEmulatorProxy
uv sync
```

---

## Usage

### Run from source

```bash
uv run main.py
```

Then open your browser at [http://localhost:8081](http://localhost:8081).

### Run the packaged executable

Download the latest release or build it yourself (see [Packaging](#packaging)), then simply run `main.exe`.

### Using the UI

Each stored account appears as a card. For each account you can:

| Option | Description |
|---|---|
| **Local interface** | Select which network interface Dofus will use (useful for multi-IP setups) |
| **Proxy URL** | Optional SOCKS5 proxy for this account (`socks5://user:pass@host:port`) |
| **Launch / Stop** | Start or kill the Dofus instance for this account |

The card border turns green while the game is running. If the game process exits on its own, the card resets automatically.

> **Note:** You can launch multiple accounts simultaneously, each with its own proxy and interface.

---

## Packaging

Build a standalone `.exe` with PyInstaller:

```bash
uv run pyinstaller main.spec
```

The output will be in the `dist/` folder.

---

## Development

### Install dev dependencies

```bash
uv sync --group dev
```

### Regenerate Thrift bindings

If `resources/zaap.thrift` changes, regenerate the Python bindings:

```bash
thrift --gen py resources/zaap.thrift && mv gen-py ankama_launcher_emulator/gen_zaap
```

### Inspect the Ankama Launcher source

To explore the launcher's internals, extract the `app.asar` bundle:

```bash
asar extract "C:/Program Files/Ankama/Ankama Launcher/resources/app.asar" "<output_dir>"
```

---

## Use as a library

Add the package to your own project:

```bash
pip install git+https://github.com/Valentin-alix/AnkamaLauncherEmulatorProxy
```
