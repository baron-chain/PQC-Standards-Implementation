"""PQC TLS 1.3 Integration Layer.

Provides PQC key exchange and signature components for TLS 1.3 handshakes.
"""

from pqctls.named_groups import (
    NamedGroup,
    ALL_NAMED_GROUPS,
    named_group_from_code_point,
    generate_key_share,
    complete_key_exchange,
    recover_shared_secret,
    key_share_size,
)

from pqctls.sig_algorithms import (
    SignatureAlgorithm,
    ALL_SIGNATURE_ALGORITHMS,
    signature_algorithm_from_code_point,
    generate_signing_key,
    sign_handshake,
    verify_handshake,
)

from pqctls.cipher_suites import (
    AeadAlgorithm,
    CipherSuite,
    TLS_AES_128_GCM_SHA256_MLKEM768,
    TLS_AES_256_GCM_SHA384_X25519MLKEM768,
    ALL_CIPHER_SUITES,
    cipher_suite_by_id,
)
