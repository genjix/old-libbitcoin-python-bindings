import bitcoin
import chain
import fuzzed

class App:

    def __init__(self):
        self.bdb_chain = bitcoin.bdb_blockchain("database")
        self.chain = chain.sync_blockchain(self.bdb_chain)

    def show_chains(self):
        print 'Current main chain ----------------------'
        for depth in range(1, self.chain.last_depth() + 1):
            blk = self.chain.block_by_depth(depth)
            if type(blk) == bitcoin.error_code:
                print str(blk)
            print bitcoin.hash_block_header(blk)

        print 'Chain 1 ---------------------------------'
        for blk in fuzzed.chain_1:
            print bitcoin.hash_block_header(blk)

        print 'Chain 2 ---------------------------------'
        for blk in fuzzed.chain_2:
            print bitcoin.hash_block_header(blk)

        print 'Chain 3 ---------------------------------'
        for blk in fuzzed.chain_3:
            print bitcoin.hash_block_header(blk)

    def show_txs(self):
        txs = []
        for depth, blk in enumerate(fuzzed.chain_1):
            for index, t in enumerate(blk.transactions):
                desc = 'c1 b%s i%s'%(depth + 1, index)
                txs.append((desc, bitcoin.hash_transaction(t)))

        for depth, blk in enumerate(fuzzed.chain_2):
            for index, t in enumerate(blk.transactions):
                desc = 'c2 b%s i%s'%(depth + 1, index)
                txs.append((desc, bitcoin.hash_transaction(t)))

        for depth, blk in enumerate(fuzzed.chain_3):
            for index, t in enumerate(blk.transactions):
                desc = 'c3 b%s i%s'%(depth + 1, index)
                txs.append((desc, bitcoin.hash_transaction(t)))

        for desc, th in txs:
            chl = self.chain.transaction(th)
            if type(chl) == bitcoin.transaction:
                print 'Found', desc
            else:
                print 'Bad', desc

if __name__ == '__main__':
    a = App()
    a.show_chains()
    a.show_txs()

