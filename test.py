import bitcoin

def handle_send(ec):
    if ec:
        print ec

def read_version_reply(ec, vers):
    if ec:
        print ec
        return
    print vers.address_me.ip
    print vers.user_agent

chan = None

def handle_connect(ec, channel):
    if ec:
        print ec
    vers = bitcoin.version()
    vers.version = 60000
    vers.services = 1
    vers.address_me.servies = 1
    vers.address_me.ip = \
        [0, 0, 0, 0, 0, 0, 0, 0, 
         0, 0, 255, 255, 127, 0, 0, 1]
    vers.address_me.port = 8333
    vers.address_you.services = 1
    vers.address_you.ip = \
        [0, 0, 0, 0, 0, 0, 0, 0, 
         0, 0, 255, 255, 127, 0, 0, 1]
    vers.address_you.port = 8333
    vers.user_agent = "/libbitcoin:0.4/example:1/";
    vers.start_height = 0
    vers.nonce = 42
    channel.send_version(vers, handle_send)
    chan = channel
    channel.subscribe_version(read_version_reply)
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
#hs = bitcoin.handshake()
#hs.connect(net, "localhost", 8333, handle_connect)
net.connect("localhost", 8333, handle_connect)
raw_input()

