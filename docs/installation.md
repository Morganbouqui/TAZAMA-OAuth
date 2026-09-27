# Installation

TAZAMA-OAuth requires Python 3.12 or newer.

## Linux/macOS development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
tazama-oauth --version
tazama-oauth --help
```

## Windows PowerShell development

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
tazama-oauth --version
tazama-oauth --help
```

A normal release install will use the same `tazama-oauth` console entry point. Do not install into or share runtime state with the existing TAZAMA application.
