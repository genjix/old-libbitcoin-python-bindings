import bitcoin

def last(ec, num):
    print ec
    print num

chain = bitcoin.bdb_blockchain("/home/genjix/libbitcoin/database")
chain.fetch_last_depth(last)

raw_input()

