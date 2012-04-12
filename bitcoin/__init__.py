import threading, Queue as queue
from _bitcoin import *
from bind import bind, _1, _2, _3

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

    def run(self):
        while True:
            work = self.queue.get()
            work()
            self.queue.task_done()

    def post(self, handler):
        self.queue.put(handler)

class ForwardWrap:

    def __init__(self, execute, handler):
        self.execute = execute
        self.handler = handler

    def __call__(self, *args, **kwargs):
        self.handler.bind(args, kwargs)
        self.execute(self.handler)

class Composed:

    def __init__(self, handler, args, kwargs):
        self.handler = handler
        self.args = args
        self.kwargs = kwargs

    def bind(self, args, kwargs):
        self.args += args
        self.kwargs = dict(self.kwargs.items() + kwargs.items())

    def __call__(self):
        self.handler(*self.args, **self.kwargs)

class Strand:

    def __init__(self, service):
        self.service = service
        self.exclude = threading.Lock()

    def execute(self, handler):
        with self.exclude:
            handler()

    def post(self, handler):
        self.service.post(bind(self.execute, handler))

    def wrap(self, handler, *args, **kwargs):
        bounded = Composed(handler, args, kwargs)
        return ForwardWrap(self.execute, bounded)

