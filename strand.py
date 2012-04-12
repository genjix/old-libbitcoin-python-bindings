import bitcoin

def foo(a):
    print "hello", a

ass = bitcoin.async_service(2)
s = bitcoin.strand(ass)
f = s.wrap(foo)
print f
f(1)
raw_input()

