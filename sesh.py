import bitcoin
import sys
import time

def handle_start(ec):
    if ec:
        print ec

def handle_stop(ec):
    if ec:
        print ec

network_service = bitcoin.async_service(1)
disk_service = bitcoin.async_service(1)
mempool_service = bitcoin.async_service(1)

hosts = bitcoin.hosts(network_service)
handshake = bitcoin.handshake(network_service)
network = bitcoin.network(network_service)
protocol = bitcoin.protocol(network_service, hosts, handshake, network)

database_path = "/home/genjix/libbitcoin/database"
blockchain = bitcoin.bdb_blockchain(disk_service, database_path)
poller = bitcoin.poller(blockchain)
transaction_pool = bitcoin.transaction_pool(mempool_service, blockchain)

def handle_confirm(ec):
    if ec:
        print "Confirm error:", ec
    else:
        print "Confirmed"

def handle_mempool_store(ec, tx_hash):
    if ec:
        print "Error storing memory pool transaction ", tx_hash, ec
    else:
        print "Accepted transaction", tx_hash

def recv_tx(ec, tx, node):
    if ec:
        print ec
        return
    transaction_pool.store(tx, handle_confirm,
        bitcoin.bind(handle_mempool_store, bitcoin._1,
                     bitcoin.hash_transaction(tx)))
    node.subscribe_transaction(
        bitcoin.bind(recv_tx, bitcoin._1, bitcoin._2, node))

def monitor_tx(node):
    node.subscribe_transaction(
        bitcoin.bind(recv_tx, bitcoin._1, bitcoin._2, node))
    protocol.subscribe_channel(monitor_tx)

protocol.subscribe_channel(monitor_tx)
session = bitcoin.session(hosts, handshake, network, protocol,
                          blockchain, poller, transaction_pool)
session.start(handle_start)

raw_input()
session.stop(handle_stop)
print "Exiting..."
time.sleep(2)

