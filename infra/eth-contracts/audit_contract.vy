event Audit:
    ipfs_address: Bytes[34]

owner: address

@external
def __init__():
    self.owner = msg.sender

@external
@view
def log_audit(ipfs_address: Bytes[34]):
    assert msg.sender == self.owner, "caller not owner"
    log Audit(ipfs_address)
