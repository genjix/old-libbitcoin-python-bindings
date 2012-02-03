CC = g++ -fPIC -Wall -ansi `pkg-config --cflags libbitcoin` -I/usr/include/python2.7 

default:
	mkdir -p bitcoin
	$(CC) -c main.cpp -o main.o
	$(CC) -shared -Wl,-soname,_bitcoin.so main.o -lpython2.7 -lboost_python `pkg-config --libs libbitcoin` -lboost_thread -o bitcoin/_bitcoin.so

