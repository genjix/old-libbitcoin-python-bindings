import bitcoin
import chain
import fuzzed

bdb_chain = bitcoin.bdb_blockchain("database")
chain = chain.sync_blockchain(bdb_chain)
print 'Current main chain ----------------------'
for depth in range(1, chain.last_depth() + 1):
    blk = chain.block_by_depth(depth)
    print bitcoin.hash_block_header(blk)

print 'Chain 1 ---------------------------------'
for blk in fuzzed.chain_1:
    print bitcoin.hash_block_header(blk)

print 'Chain 2 ---------------------------------'
for blk in fuzzed.chain_2:
    print bitcoin.hash_block_header(blk)

txs = []
for depth, blk in enumerate(fuzzed.chain_1):
    for index, t in enumerate(blk.transactions):
        desc = 'c1 b%s i%s'%(depth + 1, index)
        txs.append((desc, bitcoin.hash_transaction(t)))

for depth, blk in enumerate(fuzzed.chain_2):
    for index, t in enumerate(blk.transactions):
        desc = 'c2 b%s i%s'%(depth + 1, index)
        txs.append((desc, bitcoin.hash_transaction(t)))

for desc, th in txs:
    chl = chain.transaction(th)
    if type(chl):
        print 'Found', desc
    else:
        print 'Bad', desc

