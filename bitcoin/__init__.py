import threading, Queue as queue
from _bitcoin import *
from bind import bind, _1, _2, _3, placeholder

# Turn off libbitcoin output
disable_logging()

class output_point(input_point):
    pass

def data_chunk(strval=""):
    if len(strval) % 2 != 0:
        raise IndexError("bytes representation must be multiple of 2")
    return bytes_from_pretty(strval)

def hash_digest(strval=""):
    if len(strval) != 2 * 32:
        raise indexerror("length of hash_digest representation should be 2 * 32 characters")
    return hash_digest_from_pretty(strval)

def short_hash(strval):
    if len(strval) != 2 * 20:
        raise indexerror("length of short_hash representation should be 2 * 20 characters")
    return short_hash_from_pretty(strval)

class AsyncService(threading.Thread):

    def __init__(self):
        self.queue = queue.Queue()
        super(AsyncService, self).__init__()
        self.daemon = True
        self.start()
        self.alive_lock = threading.Lock()
        self.alives = []

    def run(self):
        while True:
            work = self.queue.get()
            work()
            self.queue.task_done()
            with self.alive_lock:
                self.alives = [obj for obj in self.alives if not obj.stopped()]

    def post(self, handler):
        self.queue.put(handler)

    def keep_alive(self, obj):
        with self.alive_lock:
            self.alives.append(obj)

class ForwardWrap:

    def __init__(self, execute, handler):
        self.execute = execute
        self.handler = handler
        self._stopped = False

    def __call__(self, *args):
        self.handler.bind(args)
        self.execute(self.handler)
        self._stopped = True

    def stopped(self):
        return self._stopped

class Composed:

    def __init__(self, handler, args):
        self.handler = handler
        self.args = args

    def bind(self, args):
        new_args = []
        for arg in self.args:
            if isinstance(arg, placeholder):
                new_args.append(args[arg.pos])
            else:
                new_args.append(arg)
        self.args = new_args

    def __call__(self):
        self.handler(*self.args)

class Strand:

    def __init__(self, service):
        self.service = service
        self.exclude = threading.Lock()

    def execute(self, handler):
        with self.exclude:
            self.service.post(handler)

    def post(self, handler):
        self.service.post(bind(self.execute, handler))

    def wrap(self, handler, *args):
        bounded = Composed(handler, args)
        fwrap = ForwardWrap(self.execute, bounded)
        self.service.keep_alive(fwrap)
        return fwrap

