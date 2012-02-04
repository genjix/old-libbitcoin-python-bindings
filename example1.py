import bitcoin
import time

class Application:

    def __init__(self):
        self.stopped = False
        self.net = bitcoin.network()
        self.channel = None

    def start(self):
        self.net.connect("localhost", 8333, self.handle_connect)

    def stop(self):
        self.stopped = True

    def is_stopped(self):
        return self.stopped

    def create_version_message(self):
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
        return vers

    # First we send our version message then the node will reply back
    def handle_connect(self, ec, channel):
        # check the error_code
        if ec:
            print 'Could not connect:', ec
            self.stop()
            return
        self.channel = channel
        version_message = self.create_version_message()
        self.channel.send_version(version_message, self.handle_send)
        self.channel.subscribe_version(self.read_version_reply)

    def handle_send(self, ec):
        if ec:
            print 'Problem sending:', ec
            self.stop()

    def read_version_reply(self, ec, vers):
        if ec:
            print 'Problem in reply:', ec
            self.stop()
            return
        # Display the version message back
        print vers.address_me.ip
        self.stop()

if __name__ == "__main__":
    app = Application()
    app.start()
    while not app.is_stopped():
        time.sleep(0.1)

