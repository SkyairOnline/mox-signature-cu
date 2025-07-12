import boa
from script.deploy_merkle import deploy_merkle
import pytest
from src import snek_token
from eth_account import Account

ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

@pytest.fixture
def merkle():
    return deploy_merkle()

@pytest.fixture
def token(merkle):
    return snek_token.at(merkle.AIRDROP_TOKEN())

@pytest.fixture
def user():
    account = Account.from_key(ANVIL_KEY)
    with boa.env.prank(account.address):
        yield account