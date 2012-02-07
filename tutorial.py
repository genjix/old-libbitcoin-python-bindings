import bitcoin
import time

class Application:

    def __init__(self):
        self.stopped = False
        # Create network service
        self.net = bitcoin.network()
        # Our current channel
        self.channel = None

    def start(self):
        # Use the network service to connect to 1 node
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

    def handle_connect(self, ec, channel):
        # Check the error_code object
        if ec:
            # Print the error and exit!
            print "Could not connect:", ec
            self.stop()
            return
        # Store our channel so it persists until the operation is complete
        self.channel = channel
        # Create the version message we will send
        version_message = self.create_version_message()
        # Send the version.
        # Function returns immediately because it is asynchronous
        self.channel.send_version(version_message, self.handle_send)
        # Express an interest in version packets from this node
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
        # We have the remote bitcoin node's version message
        # Print their IP address and user agent
        print "Remote IP:", vers.address_you.ip
        # We reached our goal. The program is complete and now stops
        self.stop()

if __name__ == "__main__":
    app = Application()
    app.start()
    while not app.is_stopped():
        time.sleep(0.1)

