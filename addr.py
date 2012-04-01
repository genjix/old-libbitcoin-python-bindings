import bitcoin

pubkey = bitcoin.data_chunk("04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5")
addr = bitcoin.payment_address()
addr.set_public_key(pubkey)
assert(addr.encoded() == "1VayNert3x1KzbpzMGt2qdqrAThiRovi8")

pubkey_hash = bitcoin.short_hash("3a775c1d2eb6123bc774cfcbeeb9ddc30179416e")
addr1 = bitcoin.payment_address()
addr1.set_public_key_hash(pubkey_hash)
assert(addr1.encoded() == "16L9BPjFJ1zbVzpoxGrNrkQea6xL9optR7")

addr2 = bitcoin.payment_address()
addr2.set_encoded("16L9BPjFJ1zbVzpoxGrNrkQea6xL9optR7")
assert(str(addr2.hash()) == "3a775c1d2eb6123bc774cfcbeeb9ddc30179416e")
assert(str(addr2.type()) == "pubkey_hash")

