import os
import secrets
import shutil
import tempfile
from pathlib import Path

from app.crypto import EncryptedSecret, SecretCipher


class EncryptedFileStore:
    def __init__(self, root: str, cipher: SecretCipher) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cipher = cipher

    def save_plaintext(self, plaintext_path: Path) -> tuple[str, EncryptedSecret, int]:
        data = bytearray(plaintext_path.read_bytes())
        try:
            encrypted = self.cipher.encrypt(bytes(data))
        finally:
            for index in range(len(data)):
                data[index] = 0
            plaintext_path.unlink(missing_ok=True)
        name = f"{secrets.token_hex(8)}.bin"
        destination = self.root / name
        destination.write_bytes(encrypted.ciphertext)
        os.chmod(destination, 0o600)
        return name, encrypted, destination.stat().st_size

    def decrypt_to_temporary(self, name: str, nonce: bytes, tag: bytes) -> Path:
        encrypted = self.root.joinpath(name).read_bytes()
        plaintext = bytearray(self.cipher.decrypt(encrypted, nonce, tag))
        fd, path = tempfile.mkstemp(prefix="tsecret-send-", dir=tempfile.gettempdir())
        try:
            os.write(fd, plaintext)
        finally:
            os.close(fd)
            for index in range(len(plaintext)):
                plaintext[index] = 0
        return Path(path)

    def delete(self, name: str | None) -> None:
        if not name:
            return
        target = self.root.joinpath(name).resolve()
        if target.parent == self.root.resolve():
            target.unlink(missing_ok=True)

    def clone_encrypted(self, name: str) -> str:
        source = self.root.joinpath(name).resolve()
        if source.parent != self.root.resolve():
            raise ValueError("invalid encrypted file path")
        clone_name = f"{secrets.token_hex(8)}.bin"
        destination = self.root / clone_name
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o600)
        return clone_name
