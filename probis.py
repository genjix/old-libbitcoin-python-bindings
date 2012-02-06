import bitcoin
import time

class Application:

    def __init__(self):
        self.net = bitcoin.network()
        self.channel = None

    def start(self):
        self.net.connect("localhost", 9292, self.handle_connect)

    # First we send our version message then the node will reply back
    def handle_connect(self, ec, channel):
        # check the error_code
        if ec:
            print 'Could not connect:', ec
            return
        self.channel = channel
        raw_tx_repr = "010000000187493c4c15c76df9f69ddd7aeb7ffbcddad4b7a979210f19602282d5b9862581000000008a47304402202d9e9f75be9c8a4c4304931b032e1de83fd2c6af2c1154a3d2b885efd5c3bfda02201184139215fb74499eae9c71ae86354c41b4d20b95a6b1fffcb8f1c5f051288101410497d11f5c33adb7c3fed0adc637358279de04f72851b7b93fb4a8655613729047c7e2908966551b5fb7f6899f6c3dd358b57eb20a61b2c9909aa106eac6310f9fffffffff0140420f00000000001976a91407e761706c63b36e5a328fab1d94e9397f40704d88b000000000"
        raw_tx = bitcoin.data_chunk(raw_tx_repr)
        ex = bitcoin.satoshi_exporter()
        tx = ex.load_transaction(raw_tx)
        print "txhash", bitcoin.hash_transaction(tx)
        self.channel.send_transaction(tx, self.handle_send)
        #self.channel.send_version(version_message, self.handle_send)
        #self.channel.subscribe_version(self.read_reply)

    def handle_send(self, ec):
        if ec:
            print 'Problem sending:', ec

    def read_reply(self, ec, vers):
        if ec:
            print 'Problem in reply:', ec
            return
        # Display the version message back

if __name__ == "__main__":
    app = Application()
    app.start()
    raw_input()

