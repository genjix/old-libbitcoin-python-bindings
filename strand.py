from bitcoin import AsyncService, Strand
from bitcoin import bind, _1, _2

def foo(a):
    print "hello", a

os = AsyncService()
s = Strand(os)
f = s.wrap(foo, 110)
f()

print "Started."
raw_input()
print "Stopping..."

