import bitcoin

raw_tx_repr = "010000000187493c4c15c76df9f69ddd7aeb7ffbcddad4b7a979210f19602282d5b9862581000000008a47304402202d9e9f75be9c8a4c4304931b032e1de83fd2c6af2c1154a3d2b885efd5c3bfda02201184139215fb74499eae9c71ae86354c41b4d20b95a6b1fffcb8f1c5f051288101410497d11f5c33adb7c3fed0adc637358279de04f72851b7b93fb4a8655613729047c7e2908966551b5fb7f6899f6c3dd358b57eb20a61b2c9909aa106eac6310f9fffffffff0140420f00000000001976a91407e761706c63b36e5a328fab1d94e9397f40704d88b000000000"
raw_tx = bitcoin.data_chunk(raw_tx_repr)
print raw_tx
print len(raw_tx)

ex = bitcoin.satoshi_exporter()
tx = ex.load_transaction(raw_tx)
print "txhash", bitcoin.hash_transaction(tx)
print tx
print ex.save_transaction(tx)
print len(ex.save_transaction(tx))
assert str(ex.save_transaction(tx)) == raw_tx_repr

print 'blk'
blk = bitcoin.genesis_block()
print bitcoin.hash_block_header(blk)
rawblk = ex.save_block(blk)
blk2 = ex.load_block(rawblk)
print bitcoin.hash_block_header(blk2)
print bitcoin.hash_transaction(blk.transactions[0])
print bitcoin.hash_transaction(blk2.transactions[0])
assert str(ex.save_block(blk2)) == str(rawblk)

getblocks = bitcoin.get_blocks()
getblocks.start_hashes.append(bitcoin.hash_block_header(blk))
getblocks.start_hashes.append(bitcoin.hash_transaction(blk.transactions[0]))
getblocks.hash_stop = bitcoin.null_hash
rawgb = ex.save_get_blocks(getblocks)
gb2 = ex.load_get_blocks(rawgb)
print gb2.start_hashes[0]
print gb2.start_hashes[1]
print gb2.hash_stop

iv1 = bitcoin.inventory_vector()
iv1.hash = gb2.start_hashes[0]
iv1.type = bitcoin.inventory_type.block
iv2 = bitcoin.inventory_vector()
iv2.hash = gb2.start_hashes[1]
iv2.type = bitcoin.inventory_type.transaction
getdata = bitcoin.get_data()
getdata.inventories.append(iv1)
getdata.inventories.append(iv2)
gdraw = ex.save_get_data(getdata)
gd2 = ex.load_get_data(gdraw)
gd2r = ex.save_get_data(gd2)
assert str(gd2r) == str(gdraw)
print gd2.inventories[1].hash, gd2.inventories[1].type
print bitcoin.inventory_type.block
inv = ex.load_inventory(gd2r)
ir = ex.save_inventory(inv)
assert str(ir) == str(gdraw)

addr = bitcoin.address()
ad = bitcoin.network_address()
ad1 = bitcoin.network_address()
addr.addresses.append(ad)
addr.addresses.append(ad1)
rawad = ex.save_address(addr)
addr1 = ex.load_address(rawad)
print 'address'
print str(rawad)
print ex.save_address(addr1)
print 'foo'
assert str(ex.save_address(addr1)) == str(rawad)

