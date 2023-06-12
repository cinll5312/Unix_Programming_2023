CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC 
LDFLAGS = -ldl 
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS) 

sandbox.so : sandbox.o 
	$(CC) -o $@ -shared $^ $(LDFLAGS)

cat1:
	./launcher ./sandbox.so config.txt cat /home/nctu/wen/unix_programming/lab/hw1/config.txt
cat2:
	./launcher ./sandbox.so config.txt cat /etc/passwd
cat3:
	./launcher ./sandbox.so config.txt cat /etc/shadow
cat4 :
	./launcher ./sandbox.so config.txt cat /etc/hosts
cat5:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem
con:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1
con1:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1
sys:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'
clean : 
	rm sandbox.so
	rm sandbox.o