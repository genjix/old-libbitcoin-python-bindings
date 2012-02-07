import bitcoin
import time

class sync_blockchain:

    def __init__(self, chain):
        self.chain = chain
        self.fetched_item = None

    def stall(self):
        while self.fetched_item is None:
            time.sleep(0.01)

    def store(self, block):
        self.fetched_item = None
        self.chain.store(block, self.handle_store)
        self.stall()
        return self.fetched_item

    def handle_store(self, ec, block_info):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = block_info

    def block_by_depth(self, depth):
        self.fetched_item = None
        self.chain.fetch_block_by_depth(depth,
            self.handle_fetch_block_by_depth)
        self.stall()
        return self.fetched_item

    def handle_fetch_block_by_depth(self, ec, block):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = block

    def block_by_hash(self, hash):
        self.fetched_item = None
        self.chain.fetch_block_by_hash(hash,
            self.handle_fetch_block_by_hash)
        self.stall()
        return self.fetched_item

    def handle_fetch_block_by_hash(self, ec, block):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = block

    def last_depth(self):
        self.fetched_item = None
        self.chain.fetch_last_depth(self.handle_fetch_last_depth)
        self.stall()
        return self.fetched_item

    def handle_fetch_last_depth(self, ec, last_depth):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = last_depth

    def block_locator(self):
        self.fetched_item = None
        self.chain.fetch_block_locator(self.handle_fetch_block_locator)
        self.stall()
        return self.fetched_item

    def handle_fetch_block_locator(self, ec, locator):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = locator

    def transaction(self, tx_hash):
        self.fetched_item = None
        self.chain.fetch_transaction(tx_hash, self.handle_fetch_transaction)
        self.stall()
        return self.fetched_item

    def handle_fetch_transaction(self, ec, tx):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = tx

    def transaction_index(self, tx_hash):
        self.fetched_item = None
        self.chain.fetch_transaction_index(tx_hash, 
            self.handle_fetch_transaction_index)
        self.stall()
        return self.fetched_item

    def handle_fetch_transaction_index(self, ec, block_depth, index_in_block):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = (block_depth, index_in_block)

    def spend(self, outpoint):
        self.fetched_item = None
        self.chain.fetch_spend(outpoint, self.handle_fetch_spend)
        self.stall()
        return self.fetched_item

    def handle_fetch_spend(self, ec, inpoint):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = inpoint

    def outputs(self, pubkey_hash):
        self.fetched_item = None
        self.chain.fetch_outputs(pubkey_hash, self.handle_fetch_outputs)
        self.stall()
        return self.fetched_item

    def handle_fetch_outputs(self, ec, outputs):
        if ec:
            self.fetched_item = ec
        else:
            self.fetched_item = outputs

if __name__ == '__main__':
    def foo(ec, outs):
        print ec, outs

    bdb_chain = bitcoin.bdb_blockchain("/home/genjix/libbitcoin/database")
    schain = sync_blockchain(bdb_chain)
    print schain.last_depth()
    print bitcoin.hash_block_header(schain.block_by_depth(0))
    addr = bitcoin.short_hash("12ab8dc588ca9d5787dde7eb29569da63c3a238c")
    for out in schain.outputs(addr):
        print out
    out = bitcoin.output_point()
    out.hash = bitcoin.hash_digest("6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516")
    out.index = 0
    print schain.spend(out)

