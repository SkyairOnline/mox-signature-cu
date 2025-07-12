# pragma version 0.4.3
"""
@title Merkle Airdrop
@license MIT
"""

from snekmate.utils import merkle_proof_verification
from snekmate.utils import eip712_domain_separator as eip712
from snekmate.utils import ecdsa
from ethereum.ercs import IERC20

initializes: eip712

struct AirdropClaim:
    account: address
    amount: uint256

# Immutables
MERKLE_ROOT: public(immutable(bytes32))
AIRDROP_TOKEN: public(immutable(IERC20))

# Constants
PROFF_MAX_LENGTH: constant(uint8) = max_value(uint8) # 255
MESSAGE_TYPEHASH: constant(bytes32) = keccak256(
    "AirdropClaim(address account,uint256 amount)"
)
EIP712_NAME: constant(String[50]) = "Merkle Airdrop"
EIP712_VERSION: constant(String[20]) = "1"

# Storage
has_claimed: public(HashMap[address, bool]) 

event Claimed:
    account: indexed(address)
    amount: indexed(uint256)

@deploy
def __init__(_merkle_root: bytes32, _airdrop_token: address):
    eip712.__init__(EIP712_NAME, EIP712_VERSION)

    MERKLE_ROOT = _merkle_root
    AIRDROP_TOKEN = IERC20(_airdrop_token)

@external
def claim(
    account: address,
    amount: uint256,
    merkle_proof: DynArray[bytes32, PROFF_MAX_LENGTH],
    v: uint8,
    r: bytes32,
    s: bytes32
):
    """
    Allow users to claim their airdrop tokens.
    """
    assert not self.has_claimed[account], "Merkle Airdrop: Account has already claimed"

    message_hash: bytes32 = self._get_message_hash(account, amount)
    assert self._is_valid_signature(account, message_hash, v, r, s), "Merkle Airdrop: Invalid signature"

    leaf: bytes32 = keccak256(abi_encode(keccak256(abi_encode(account, amount))))
    assert merkle_proof_verification._verify(merkle_proof, MERKLE_ROOT, leaf), "Merkle Airdrop: Invalid Merkle proof"

    self.has_claimed[account] = True
    log Claimed(account=account, amount=amount)

    success: bool = extcall AIRDROP_TOKEN.transfer(account, amount)
    assert success, "Merkle Airdrop: Transfer failed"

@external
@view
def get_message_hash(account: address, amount: uint256) -> bytes32:
    return self._get_message_hash(account, amount)

@internal
def _is_valid_signature(account: address, message_hash: bytes32, v: uint8, r: bytes32, s: bytes32) -> bool:
    v_u: uint256 = convert(v, uint256)
    r_u: uint256 = convert(r, uint256)
    s_u: uint256 = convert(s, uint256)
    actual_signer: address = ecdsa._try_recover_vrs(message_hash, v_u, r_u, s_u)
    return actual_signer == account

@internal
@view
def _get_message_hash(account: address, amount: uint256) -> bytes32:
    return eip712._hash_typed_data_v4(
        keccak256(abi_encode(MESSAGE_TYPEHASH, AirdropClaim(
            account=account,
            amount=amount
        ))),
    )