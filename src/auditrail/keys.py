"""Ed25519 keys for the recorder (ledger + anchor signatures) and for agents (messages).

Why signatures at all: a plain hash chain can be recomputed by anyone who can
write the file, so on its own it only catches careless edits. A signature made
with a key the agent process never sees means rewriting the ledger also needs
that key. Keep the private key in a separate process, OS user, KMS, or TPM;
see docs/spec/evidence-format-v2.md section 6.

Key files are plain hex so a verifier in any language can read them:
  <name>.key  64 hex chars, the 32-byte Ed25519 seed (keep private)
  <name>.pub  64 hex chars, the 32-byte public key (publish this)

Every signed message is prefixed with a domain-separation tag, so a signature
made for one purpose (say, a record) can never be replayed as another (an anchor).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Mapping, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

TAG_RECORD = b"auditrail/record/v2\n"
TAG_ANCHOR = b"auditrail/anchor/v2\n"
TAG_A2A = b"auditrail/a2a/v2\n"
TAG_RECEIPT = b"auditrail/receipt/v2\n"


def key_id_for(public_hex: str) -> str:
    """Short, stable identifier for a public key: first 16 hex chars of sha256(raw key)."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


class Signer:
    """Holds one Ed25519 private key. Never pass this object into agent code."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        raw_pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_hex = raw_pub.hex()
        self.key_id = key_id_for(self.public_hex)

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Signer":
        """Deterministic key from a 32-byte seed. Used for test vectors only."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike]) -> "Signer":
        seed_hex = Path(path).read_text(encoding="utf-8").strip()
        return cls.from_seed(bytes.fromhex(seed_hex))

    def seed_hex(self) -> str:
        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

    def sign(self, tag: bytes, message: bytes) -> str:
        return self._key.sign(tag + message).hex()

    def save(self, prefix: Union[str, os.PathLike]) -> tuple[Path, Path]:
        """Write <prefix>.key (owner-only where the OS supports it) and <prefix>.pub."""
        prefix = Path(prefix)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        key_path = prefix.with_name(prefix.name + ".key")
        pub_path = prefix.with_name(prefix.name + ".pub")
        if key_path.exists():
            raise FileExistsError(f"{key_path} already exists; refusing to overwrite a private key")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(self.seed_hex() + "\n")
        pub_path.write_text(self.public_hex + "\n", encoding="utf-8")
        return key_path, pub_path


def verify_sig(public_hex: str, tag: bytes, message: bytes, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(sig_hex), tag + message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_public_keys(paths) -> dict[str, str]:
    """Read .pub files into {key_id: public_hex}."""
    keys: dict[str, str] = {}
    for p in paths or ():
        pub = Path(p).read_text(encoding="utf-8").strip()
        bytes.fromhex(pub)  # fail early on a malformed file
        keys[key_id_for(pub)] = pub
    return keys


class KeyRegistry:
    """Maps agent identities to their public keys, for verifying agent messages.

    A registry is the trust decision: whoever controls it decides which key
    speaks for which agent. Distribute it the same way you distribute any
    other trust anchor (signed config, a repo with review, your secrets manager).
    """

    def __init__(self, agents: Optional[Mapping[str, str]] = None):
        self._by_agent: dict[str, str] = dict(agents or {})

    def add(self, agent_id: str, public_hex: str) -> None:
        self._by_agent[agent_id] = public_hex

    def public_key(self, agent_id: str) -> Optional[str]:
        return self._by_agent.get(agent_id)
