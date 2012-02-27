import bitcoin

def start_polling(ec, node, poll):
    if ec:
        print ec
        return
    poll.query(node)

if __name__ == "__main__":
    s1 = bitcoin.async_service(1)
    s2 = bitcoin.async_service(1)
    chain = bitcoin.bdb_blockchain(s1, "database")
    poll = bitcoin.poller(chain)
    net = bitcoin.network(s2)
    hs = bitcoin.handshake(s2)
    hs.connect(net, "localhost", 8333,
        bitcoin.bind(start_polling, bitcoin._1, bitcoin._2, poll))
    raw_input()

