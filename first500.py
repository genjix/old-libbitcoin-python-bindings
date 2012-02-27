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
    # Re-subscribe to receive further inventory packets.
    # Bitcoin nodes can respond with any number of hashes split over
    # any number of batches.
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
    # 1. Connected to other node
    # 2. Performed version/verack handshake process
    # Node is now ready and communicating with us
    node.send_get_blocks(create_get_blocks_message(),
         bitcoin.bind(handle_send_get_blocks, bitcoin._1))
    node.subscribe_inventory(
        bitcoin.bind(receive_inv, bitcoin._1, bitcoin._2, node))
    hs.fetch_network_address(show_ip)

def handle_init(ec, hs, net):
    if ec:
        error_exit(ec)
    # Main program thread begins here
    hs.connect(net, "localhost", 8333,
        bitcoin.bind(handle_handshake, bitcoin._1, bitcoin._2, hs))

if __name__ == "__main__":
    s = bitcoin.async_service(1)
    net = bitcoin.network(s)
    hs = bitcoin.handshake(s)
    hs.start(bitcoin.bind(handle_init, bitcoin._1, hs, net))
    raw_input()

