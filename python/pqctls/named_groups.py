"""PQC Named Groups for TLS 1.3 key exchange.

Defines PQC and hybrid named groups for the supported_groups extension
(ClientHello/ServerHello), along with key share generation and exchange
completion helpers.
"""

import sys
import os
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mlkem.kem import keygen as mlkem_keygen, encaps as mlkem_encaps, decaps as mlkem_decaps
from mlkem.params import ML_KEM_768, ML_KEM_1024
from hybrid.hybrid_kem import (
    X25519_MLKEM768, ECDHP256_MLKEM768,
    hybrid_keygen, hybrid_encaps, hybrid_decaps,
)


class NamedGroup(IntEnum):
    """TLS 1.3 named group identifiers for PQC key exchange."""
    MLKEM768 = 0x0768
    MLKEM1024 = 0x1024
    X25519MLKEM768 = 0x6399
    SecP256r1MLKEM768 = 0x639A


ALL_NAMED_GROUPS = list(NamedGroup)


def named_group_from_code_point(cp: int) -> Optional[NamedGroup]:
    """Look up a named group by its TLS code point."""
    try:
        return NamedGroup(cp)
    except ValueError:
        return None


@dataclass
class KeyShareResult:
    """Result of generating a key share."""
    private_key: bytes
    public_key_share: bytes
    classical_ek_size: int = 0
    classical_dk_size: int = 0


@dataclass
class KeyExchangeResult:
    """Result of completing a key exchange."""
    shared_secret: bytes
    response_key_share: bytes
    classical_ct_size: int = 0


def _mlkem_params(group: NamedGroup):
    if group == NamedGroup.MLKEM768:
        return ML_KEM_768
    elif group == NamedGroup.MLKEM1024:
        return ML_KEM_1024
    raise ValueError(f"Not a pure ML-KEM group: {group}")


def _hybrid_scheme(group: NamedGroup):
    if group == NamedGroup.X25519MLKEM768:
        return X25519_MLKEM768
    elif group == NamedGroup.SecP256r1MLKEM768:
        return ECDHP256_MLKEM768
    raise ValueError(f"Not a hybrid group: {group}")


def generate_key_share(group: NamedGroup) -> KeyShareResult:
    """Generate a key share for the given named group."""
    if group in (NamedGroup.MLKEM768, NamedGroup.MLKEM1024):
        params = _mlkem_params(group)
        ek, dk = mlkem_keygen(params)
        return KeyShareResult(
            private_key=dk,
            public_key_share=ek,
        )
    elif group in (NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768):
        scheme = _hybrid_scheme(group)
        kp = hybrid_keygen(scheme)
        return KeyShareResult(
            private_key=kp.dk,
            public_key_share=kp.ek,
            classical_ek_size=kp.classical_ek_size,
            classical_dk_size=kp.classical_dk_size,
        )
    raise ValueError(f"Unsupported named group: {group}")


def complete_key_exchange(
    group: NamedGroup,
    peer_key_share: bytes,
    classical_ek_size: int = 0,
) -> KeyExchangeResult:
    """Complete a key exchange as the responder (ServerHello side)."""
    if group in (NamedGroup.MLKEM768, NamedGroup.MLKEM1024):
        params = _mlkem_params(group)
        ss, ct = mlkem_encaps(peer_key_share, params)
        return KeyExchangeResult(
            shared_secret=ss,
            response_key_share=ct,
        )
    elif group in (NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768):
        scheme = _hybrid_scheme(group)
        result = hybrid_encaps(scheme, peer_key_share, classical_ek_size)
        return KeyExchangeResult(
            shared_secret=result.shared_secret,
            response_key_share=result.ciphertext,
            classical_ct_size=result.classical_ct_size,
        )
    raise ValueError(f"Unsupported named group: {group}")


def recover_shared_secret(
    group: NamedGroup,
    private_key: bytes,
    peer_response: bytes,
    classical_dk_size: int = 0,
    classical_ct_size: int = 0,
) -> bytes:
    """Recover the shared secret as the initiator (ClientHello side)."""
    if group in (NamedGroup.MLKEM768, NamedGroup.MLKEM1024):
        params = _mlkem_params(group)
        return mlkem_decaps(private_key, peer_response, params)
    elif group in (NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768):
        scheme = _hybrid_scheme(group)
        return hybrid_decaps(scheme, private_key, peer_response,
                             classical_dk_size, classical_ct_size)
    raise ValueError(f"Unsupported named group: {group}")


def key_share_size(group: NamedGroup) -> int:
    """Expected public key share size for a named group."""
    if group == NamedGroup.MLKEM768:
        return ML_KEM_768.ek_size
    elif group == NamedGroup.MLKEM1024:
        return ML_KEM_1024.ek_size
    elif group == NamedGroup.X25519MLKEM768:
        return 32 + ML_KEM_768.ek_size
    elif group == NamedGroup.SecP256r1MLKEM768:
        return 65 + ML_KEM_768.ek_size
    return 0
