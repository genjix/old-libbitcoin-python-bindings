import stress_fuzz as stre
import bitcoin as b
import fuzzed as f

b.setup_bdb_blockchain("database")

a = stre.App()

def reorganize(ec, arr, repl):
    print 'Reorganize!', ec
    a.bdb_chain.subscribe_reorganize(reorganize)
    for blk in arr:
        print 'arrive', b.hash_block_header(blk)
    for blk in repl:
        print 'remove', b.hash_block_header(blk)

a.bdb_chain.subscribe_reorganize(reorganize)
chains = f.chain_1, f.chain_2, f.chain_3
#for i in range(5, -1, -1):
for i in range(6):
    print i
    for c in chains:
        print 'new chain'
        blk = c[i]
        r = a.chain.store(blk)
        #if type(r) == b.error_code:
        #    print str(r)
        #else:
        #    print r.status, r.depth, b.hash_block_header(blk)
        #print a.show_chains()
        #print a.show_txs()

r = a.chain.store(f.chain_2[6])
#print str(r)
#print r.status, r.depth
print a.show_chains()
#print a.show_txs()
