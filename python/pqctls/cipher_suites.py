"""TLS 1.3 PQC Cipher Suite definitions."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from pqctls.named_groups import NamedGroup
from pqctls.sig_algorithms import SignatureAlgorithm


class AeadAlgorithm(Enum):
    """AEAD algorithms used in TLS 1.3."""
    AES_128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256"
    AES_256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384"
    CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"

    @property
    def key_length(self) -> int:
        return {
            self.AES_128_GCM_SHA256: 16,
            self.AES_256_GCM_SHA384: 32,
            self.CHACHA20_POLY1305_SHA256: 32,
        }[self]

    @property
    def hash_length(self) -> int:
        return {
            self.AES_128_GCM_SHA256: 32,
            self.AES_256_GCM_SHA384: 48,
            self.CHACHA20_POLY1305_SHA256: 32,
        }[self]


@dataclass(frozen=True)
class CipherSuite:
    """A TLS 1.3 PQC cipher suite."""
    id: int
    name: str
    aead: AeadAlgorithm
    key_exchange: NamedGroup
    signature: SignatureAlgorithm


TLS_AES_128_GCM_SHA256_MLKEM768 = CipherSuite(
    id=0x13010768,
    name="TLS_AES_128_GCM_SHA256_MLKEM768",
    aead=AeadAlgorithm.AES_128_GCM_SHA256,
    key_exchange=NamedGroup.MLKEM768,
    signature=SignatureAlgorithm.MLDSA65,
)

TLS_AES_256_GCM_SHA384_X25519MLKEM768 = CipherSuite(
    id=0x13026399,
    name="TLS_AES_256_GCM_SHA384_X25519MLKEM768",
    aead=AeadAlgorithm.AES_256_GCM_SHA384,
    key_exchange=NamedGroup.X25519MLKEM768,
    signature=SignatureAlgorithm.MLDSA65_ED25519,
)

ALL_CIPHER_SUITES = [
    TLS_AES_128_GCM_SHA256_MLKEM768,
    TLS_AES_256_GCM_SHA384_X25519MLKEM768,
]


def cipher_suite_by_id(suite_id: int) -> Optional[CipherSuite]:
    """Look up a cipher suite by its ID."""
    for cs in ALL_CIPHER_SUITES:
        if cs.id == suite_id:
            return cs
    return None
