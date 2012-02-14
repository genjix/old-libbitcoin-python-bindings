import bitcoin
import sys

def error_exit(ec):
    sys.stderr.write("Error: %s\n"%ec)
    sys.exit(-1)

def receive_inv(ec, inv, node):
    if ec:
        error_exit(ec)
    print "Received:"
    for ivv in inv.inventories:
        if ivv.type == bitcoin.inventory_type.block:
            print ivv.hash
        else:
            print "--"
    node.subscribe_inventory(
        bitcoin.bind(receive_inv, bitcoin._1, bitcoin._2, node))

def handle_send_get_blocks(ec):
    if ec:
        error_exit(ec)
def create_get_blocks_message():
    packet = bitcoin.get_blocks()
    genesis_hash = bitcoin.hash_block_header(bitcoin.genesis_block())
    packet.start_hashes.append(genesis_hash)
    packet.hash_stop = bitcoin.null_hash
    return packet

def show_ip(ec, addr):
    if ec:
        error_exit(ec)
    print addr.ip

def handle_handshake(ec, node, hs):
    if ec:
        error_exit(ec)
    node.subscribe_inventory(
        bitcoin.bind(receive_inv, bitcoin._1, bitcoin._2, node))
    node.send_get_blocks(create_get_blocks_message(),
         bitcoin.bind(handle_send_get_blocks, bitcoin._1))
    hs.fetch_network_address(show_ip)

def handle_init(ec, hs, net):
    if ec:
        error_exit(ec)
    hs.connect(net, "localhost", 8333,
        bitcoin.bind(handle_handshake, bitcoin._1, bitcoin._2, hs))

if __name__ == "__main__":
    net = bitcoin.network()
    hs = bitcoin.handshake()
    hs.start(bitcoin.bind(handle_init, bitcoin._1, hs, net))
    raw_input()

