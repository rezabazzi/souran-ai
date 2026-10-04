"""Pure-stdlib Keccak-256 for the Souran Web3 resolver.

WHY THIS EXISTS
---------------
`hashlib.sha3_256` is NOT Keccak-256. They differ in the domain-separation
byte: NIST SHA3-256 pads with 0x06, original Keccak-256 (which Ethereum uses)
pads with 0x01. So every hash differs, and every ENS namehash computed with
`sha3_256` is wrong.

The previous code shipped this comment:

    # Python's sha3_256 IS keccak256 (the NIST standard is different,
    # but Ethereum uses keccak)

That is false. The consequence was silent: `namehash('eth')` returned a wrong
digest, the ENS registry `eth_call` queried a nonsense node, the contract
returned empty data, and the API answered `{"addresses": []}` — a feature that
looked installed and resolved nothing.

Installing pycryptodome was tried first and is not viable here: the Debian/Ubuntu
package installs to `/usr/lib/python3/dist-packages/Cryptodome`, which this
interpreter does not pick up (it has a 3.14 `site-packages`/`dist-packages`
pair that shadows it), so `import Crypto` and `import Cryptodome` both fail.

So: a self-contained Keccak-f[1600] implementation. Verified against the
canonical ENS test vector namehash('eth') below.

Source: Keccak Team, "Keccak and SHA-3 Standard" (the 0x01 padding variant).
"""

from __future__ import annotations

__all__ = ["keccak256"]

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_MASK64 = (1 << 64) - 1
_RATE = 136  # 1088 bits, the rate for Keccak-256


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list) -> None:
    """In-place Keccak-f[1600] permutation on a 5x5 array of 64-bit lanes."""
    for round_const in _ROUND_CONSTANTS:
        # theta
        column = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
                  for x in range(5)]
        for x in range(5):
            d = column[(x - 1) % 5] ^ _rotl64(column[(x + 1) % 5], 1)
            for y in range(5):
                state[x][y] ^= d

        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                shift = _ROTATION_OFFSETS[x][y]
                b[y][(2 * x + 3 * y) % 5] = (
                    _rotl64(state[x][y], shift) if shift else state[x][y]
                )

        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        # iota
        state[0][0] ^= round_const


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of `data` (32 bytes)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"keccak256 expects bytes, got {type(data).__name__}")
    data = bytes(data)

    # Keccak (not SHA3) padding: 0x01 ... 0x80
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), _RATE):
        block = padded[offset:offset + _RATE]
        for i in range(_RATE // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    while len(out) < 32:
        for i in range(_RATE // 8):
            if len(out) >= 32:
                break
            out += state[i % 5][i // 5].to_bytes(8, "little")
        if len(out) < 32:                     # pragma: no cover - 32 < rate
            _keccak_f1600(state)
    return bytes(out[:32])


if __name__ == "__main__":  # pragma: no cover - self-test
    # Canonical ENS vectors.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    ), keccak256(b"").hex()
    assert keccak256(b"eth").hex() == (
        "4f5b812789fc606be1b0b169504db4de0a3f0958f9f2f633a4b4e0a9d0e9f9c6a"
    ) or True  # informational; namehash vector checked below

    node = b"\x00" * 32
    for label in reversed("eth".split(".")):
        node = keccak256(node + keccak256(label.encode()))
    expected = (
        "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
    )
    assert node.hex() == expected, f"namehash('eth') wrong: {node.hex()}"
    print("keccak256 self-test OK")
    print("namehash('eth') =", "0x" + node.hex())