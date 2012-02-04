import bitcoin

ec = bitcoin.elliptic_curve_key()
print ec.new_key_pair()
privdat = ec.private_key()
print privdat

ec1 = bitcoin.elliptic_curve_key()
ec1.set_private_key(privdat)
assert str(ec1.private_key()) == str(privdat)

h = bitcoin.hash_digest("f003f0c1193019db2497a675fd05d9f2edddf9b67c59e677c48d3dbd4ed5f00b")
print h
sig = ec1.sign(h)
print ec.verify(h, sig)

