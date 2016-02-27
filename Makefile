all: ícmptun_client ícmptun_server

ícmptun_client: tun.c salsa20.c
	gcc -lnetfilter_queue -lnfnetlink -lpthread -lcrypto -g -O2 tun.c salsa20.c -o icmptun_client

ícmptun_server: tun.c salsa20.c
	gcc -lnetfilter_queue -lnfnetlink -lpthread -lcrypto -g -O2 tun.c salsa20.c -DSERVER -o icmptun_server

clean:
	rm -f icmptun_client icmptun_server