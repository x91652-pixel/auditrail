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
import re
from pathlib import Path
from typing import Mapping, Optional, Union

from ._strict import is_hex
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


DEFAULT_ALG = "ed25519"  # what a record or anchor without `sig_alg` means; writers never write it explicitly


class Signer:
    """Holds one Ed25519 private key. Never pass this object into agent code."""

    #: the algorithm token this signer's signatures belong to. Anything but DEFAULT_ALG is written to the record
    #: as `sig_alg`; Ed25519 never is, so default ledgers are byte-identical to what they always were.
    alg = DEFAULT_ALG

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
    # Exactly 128 lowercase hex characters. bytes.fromhex would also accept spaces and capitals,
    # which would let a signature be altered without invalidating it.
    if not is_hex(sig_hex, 128):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(sig_hex), tag + message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# Exactly the characters Rust's str::trim removes (Unicode White_Space). Python's str.strip() also removes
# U+001C..U+001F, which Rust does not, so it is not used here.
_RUST_WHITESPACE = "".join(map(chr, (
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F,
    0x3000)))


def parse_public_hex(text: str) -> str:
    """A public key as 64 lower-case hex digits, from the text of a .pub file.

    The rule is the Rust verifier's: trim surrounding whitespace, then the rest must be exactly 32 bytes of
    hexadecimal, in either case. Embedded whitespace, a 0x prefix, odd or wrong lengths are errors
    (bytes.fromhex alone would skip whitespace and check no length)."""
    trimmed = text.strip(_RUST_WHITESPACE)
    if re.fullmatch(r"[0-9a-fA-F]{64}", trimmed) is None:
        raise ValueError("a public key file must hold exactly 64 hexadecimal digits (32 bytes), "
                         "optionally surrounded by whitespace")
    return trimmed.lower()


# token -> callable(public_hex, tag, message, sig_hex) -> bool. Only the default exists. Tests may add an entry to
# exercise "one verifier knows an algorithm and the other does not"; nothing else should.
_VERIFIERS = {DEFAULT_ALG: verify_sig}


def supported_algorithms() -> frozenset:
    return frozenset(_VERIFIERS)


def verify_with(alg: str, public_hex: str, tag: bytes, message: bytes, sig_hex: str) -> bool:
    """Verify with the named algorithm; False for an algorithm this verifier does not implement."""
    fn = _VERIFIERS.get(alg)
    return fn is not None and fn(public_hex, tag, message, sig_hex)


class TrustedKeys(dict):
    """{key_id: public_hex} plus the algorithm each key belongs to ({key_id: token}; a missing entry means the
    default). load_public_keys returns a plain dict: every .pub file is an Ed25519 key."""

    def __init__(self, keys=None, algorithms=None):
        super().__init__(keys or {})
        self.algorithms = dict(algorithms or {})


def key_algorithm(public_keys, key_id: str) -> str:
    return getattr(public_keys, "algorithms", {}).get(key_id, DEFAULT_ALG)


def load_public_keys(paths) -> dict[str, str]:
    """Read .pub files into {key_id: public_hex}. A malformed file raises ValueError."""
    keys: dict[str, str] = {}
    for p in paths or ():
        try:
            pub = parse_public_hex(Path(p).read_text(encoding="utf-8"))
        except ValueError as exc:  # includes UnicodeDecodeError
            raise ValueError(f"{p}: {exc}") from exc
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
