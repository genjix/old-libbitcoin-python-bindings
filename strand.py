from bitcoin import AsyncService, Strand

def foo(a):
    print "hello", a

os = AsyncService()
s = Strand(os)
f = s.wrap(foo)
f(110)

print "Started."
raw_input()
print "Stopping..."

