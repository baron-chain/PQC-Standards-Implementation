"""ML-DSA parameter sets per FIPS 204."""

from dataclasses import dataclass


@dataclass(frozen=True)
class MLDSAParams:
    name: str
    k: int
    l: int  # noqa: E741
    eta: int
    tau: int
    beta: int
    gamma1: int
    gamma2: int
    omega: int
    lambda_: int
    d: int = 13

    @property
    def pk_size(self) -> int:
        """Public key size in bytes: 32 + 32*k*(bitlen(q-1) - d)."""
        return 32 + 32 * self.k * 10  # bitlen(q-1) - d = 23 - 13 = 10

    @property
    def sk_size(self) -> int:
        """Secret key size in bytes."""
        # 32 + 32 + 64 + 32*((l+k)*bitlen(2*eta) + d*k)
        bitlen_2eta = 4 if self.eta == 2 else 4  # bitlen(4)=3 -> ceil to nibble=4; bitlen(8)=4
        if self.eta == 2:
            eta_bits = 3
        else:
            eta_bits = 4
        return 32 + 32 + 64 + 32 * ((self.l + self.k) * eta_bits + self.d * self.k)

    @property
    def sig_size(self) -> int:
        """Signature size in bytes."""
        gamma1_bits = 18 if self.gamma1 == (1 << 17) else 20
        c_tilde_bytes = self.lambda_ // 4
        return (
            c_tilde_bytes  # c_tilde
            + 32 * self.l * gamma1_bits  # z encoding
            + self.omega + self.k  # hint encoding
        )


ML_DSA_44 = MLDSAParams(
    name="ML-DSA-44",
    k=4, l=4,
    eta=2, tau=39, beta=78,
    gamma1=1 << 17, gamma2=95232,
    omega=80, lambda_=128,
)

ML_DSA_65 = MLDSAParams(
    name="ML-DSA-65",
    k=6, l=5,
    eta=4, tau=49, beta=196,
    gamma1=1 << 19, gamma2=261888,
    omega=55, lambda_=192,
)

ML_DSA_87 = MLDSAParams(
    name="ML-DSA-87",
    k=8, l=7,
    eta=2, tau=60, beta=120,
    gamma1=1 << 19, gamma2=261888,
    omega=75, lambda_=256,
)
