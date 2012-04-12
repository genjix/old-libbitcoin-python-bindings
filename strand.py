from bitcoin import AsyncService, Strand
from bitcoin import bind, _1, _2

def foo(a, b):
    print "hello", a, b

os = AsyncService()
s = Strand(os)
f = s.wrap(foo, 110, _1)
f(4)

print "Started."
raw_input()
print "Stopping..."

