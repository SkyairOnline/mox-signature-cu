from src import snek_token, merkle_airdrop
from eth_utils import to_wei
from script.make_merkle import generate_merkle_tree

INITIAL_SUPPLY = to_wei(100, "ether")

def deploy_merkle():
    token = snek_token.deploy(INITIAL_SUPPLY)
    _, root = generate_merkle_tree()
    airdrop_contract = merkle_airdrop.deploy(root, token.address)
    token.transfer(airdrop_contract.address, INITIAL_SUPPLY)
    print(f"Token deployed at: {token.address}")
    return airdrop_contract

def moccasin_main():
    return deploy_merkle()