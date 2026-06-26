import os
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent.parent
SSH_KEY_DIR = Path(os.getenv("SSH_KEY_DIR", str(BASE_DIR / ".ssh")))
PRIVATE_KEY_PATH = SSH_KEY_DIR / "patch_manager_key"
PUBLIC_KEY_PATH = SSH_KEY_DIR / "patch_manager_key.pub"


def ensure_ssh_keypair() -> None:
    SSH_KEY_DIR.mkdir(parents=True, exist_ok=True)
    if not PRIVATE_KEY_PATH.exists():
        subprocess.run(
            [
                "ssh-keygen", "-t", "ed25519",
                "-f", str(PRIVATE_KEY_PATH),
                "-N", "",
                "-C", "patch-manager@exia.tech",
            ],
            check=True, capture_output=True,
        )
        os.chmod(str(PRIVATE_KEY_PATH), 0o600)


def get_public_key() -> str:
    if not PUBLIC_KEY_PATH.exists():
        ensure_ssh_keypair()
    return PUBLIC_KEY_PATH.read_text().strip()
