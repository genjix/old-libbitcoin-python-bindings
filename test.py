import bitcoin

def handle_connect(ec, channel):
    if ec:
        print ec
    print 'connect'

d = bitcoin.data_chunk("001212")
print d
h = bitcoin.hash_digest("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
print h
if h == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f":
    print 'Yes'
print len(h)

tx = bitcoin.transaction()
print bitcoin.hash_transaction(tx)

netaddr = bitcoin.network_address()
print netaddr.ip

s = bitcoin.script()
o = bitcoin.operation()
o.code = bitcoin.opcode.special
s.push_operation(o)
o.code = bitcoin.opcode.nop
o.data = bitcoin.data_chunk("deadbeef")
s.push_operation(o)
o = bitcoin.operation()
o.code = bitcoin.opcode.hash160
s.push_operation(o)
print s
print s.operations()
print s.type()

net = bitcoin.network()
net.connect("localhost", 8333, handle_connect)
raw_input()

