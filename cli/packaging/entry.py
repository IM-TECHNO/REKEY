"""Entry point PyInstaller freezes into the single-file `rekey` binary."""

from rekey_cli.main import app

if __name__ == "__main__":
    app()
