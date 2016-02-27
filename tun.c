#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include "ecrypt.h"

#include <netdb.h>
#include <linux/netfilter.h>
#include <linux/icmp.h>
#include <netinet/ip.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "openssl/sha.h"

#define ICMP_ID 15387
#define ICMP_SEQ 15387
#define QUEUE_ID 0
#define IP_TABLE_SIZE 50

int sock;
int tun_fd;
int server;
uint32_t server_ip;
ECRYPT_ctx cipher_ctx;

void sigterm_handler(int dummy) {
  system("iptables -D INPUT -p icmp -j QUEUE");
  exit(0);
}

struct ip_list_t {
  struct ip_list_t * next;
  uint32_t private;
  uint32_t public;
  uint16_t icmp_id;
} ip_list_t;

struct ip_list_t ** ip_table=NULL;

inline uint32_t hash_ip(uint32_t a) {
  return a%IP_TABLE_SIZE;
}

uint32_t get_dest(uint32_t private, uint16_t * icmp_id) {
  if (!ip_table) return 0;
  int idx=hash_ip(private);
  if (!ip_table[idx]) return 0;
  struct ip_list_t * tmp=ip_table[idx];
  if (tmp->private==private) {
    *icmp_id=tmp->icmp_id;
    return tmp->public;
  }
  while (tmp->next) {
    if (tmp->private==private) {
      *icmp_id=tmp->icmp_id;
      return tmp->public;
    }
    tmp=tmp->next;
  }
  return 0;
}

unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}


int register_dest(uint32_t private, uint32_t public, uint16_t id) {
  if (!ip_table) {
    ip_table = (struct ip_list_t**)malloc(IP_TABLE_SIZE*sizeof(struct ip_list_t*));
  }
  int idx=hash_ip(private);
  if (!ip_table[idx]) {
    ip_table[idx]=(struct ip_list_t*)malloc(sizeof(struct ip_list_t));
    ip_table[idx]->public=public;
    ip_table[idx]->private=private;
    ip_table[idx]->icmp_id=id;
    ip_table[idx]->next=NULL;
    return 1;
  }
  struct ip_list_t * tmp=ip_table[idx];
  if (tmp->private==private) {
    if (tmp->public==public) return 0;
    tmp->public=public;
    return 1;
  }
  while (tmp->next) {
    if (tmp->private==private) {
      if (tmp->public==public) return 0;
      tmp->public=public;
      return 1;
    }
    tmp=tmp->next;
  }
  tmp->next=ip_table[idx]=(struct ip_list_t*)malloc(sizeof(struct ip_list_t));
  ip_table[idx]->public=public;
  ip_table[idx]->private=private;
  ip_table[idx]->icmp_id=id;
  ip_table[idx]->next=NULL;
  return 1;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    int id,i;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);
    unsigned char *pktData;
    int len = nfq_get_payload(nfa, &pktData);
    if (len<sizeof(struct ip) + sizeof(struct icmphdr)+5) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //this packet is not for me
    struct ip *iph = (struct ip *)pktData;
    struct icmphdr *icmph = (struct icmphdr *)(pktData + sizeof(struct ip));
    char decr[1600];
    ECRYPT_ctx x;
    memcpy(&x,&cipher_ctx,sizeof(ECRYPT_ctx));
    uint32_t iv;
    memcpy(&iv, pktData + sizeof(struct ip) +  sizeof(struct icmphdr),4);
    long b=iv;
    ECRYPT_ivsetup(&x,(const u8 *)&b);
    ECRYPT_encrypt_bytes(&x,pktData + sizeof(struct ip) +  sizeof(struct icmphdr)+5,decr,len - sizeof(struct ip) - sizeof(struct icmphdr)-5);
    struct ip *iph_inner = (struct ip *)(decr);
    char expected_checksum=iph_inner->ip_sum%256;
    if (expected_checksum!=pktData[sizeof(struct ip) +  sizeof(struct icmphdr)+4]) {
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //this packet is not for me
    }
    int expected_type=(server)?8:0;
    if (icmph->type==expected_type && icmph->un.echo.sequence==htons(ICMP_SEQ)) {
      if (server) {
	if (register_dest(ntohl(iph_inner->ip_src.s_addr), ntohl(iph->ip_src.s_addr), icmph->un.echo.id))
	  printf("registered private IP %u to public IP %u\n",ntohl(iph_inner->ip_src.s_addr),ntohl(iph->ip_src.s_addr));
      }
      printf("received packet from %s to ", inet_ntoa(iph_inner->ip_src));
      printf("%s\n", inet_ntoa(iph_inner->ip_dst));
      write(tun_fd, decr, len - sizeof(struct ip) - sizeof(struct icmphdr)-5); //write packet to tunnel interface
      return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); //drop this packet - prevent sending standard ICMP reply
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //this packet is not for me
}

void * netfilter_thread(void * dummy) {
  struct nfq_handle* h;
  struct nfq_q_handle *qh;
  
  if (!(h = nfq_open())) {
    printf("Error in nfq_open()\n");
    exit(-1);
  }
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    printf("Error in nfq_unbind_pf()\n");
    exit(1);
  }

  if (nfq_bind_pf(h, AF_INET) < 0) {
    printf("Error in nfq_bind_pf()\n");
    exit(1);
  }
  if (!(qh = nfq_create_queue(h, QUEUE_ID, &cb, NULL))) {
    printf("Error in nfq_create_queue()\n");
    exit(1);
  }
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    printf("Could not set packet copy mode\n");
    exit(1);
  }

  char buf[1600];
  int rv, fd=nfq_fd(h);
  for (;;) {
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
	nfq_handle_packet(h, buf, rv); /* send packet to callback */
    }
  }
  
  nfq_destroy_queue(qh);
  nfq_close(h);
}

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
   if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
     printf("/dev/net/tun: no such file\nis kernel module tun active?\n");
     exit(1);
   }
   memset(&ifr, 0, sizeof(ifr));
   ifr.ifr_flags = flags;
   if (*dev) {
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
     printf("TUNSETIFF failed\ncould not create tunnel device\n");
     close(fd);
     exit(1);
   }

  strcpy(dev, ifr.ifr_name);
  return fd;
}

int main(int argc, char ** argv) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
#ifdef SERVER
  server=1;
  if (argc<2) {
    printf("Usage: ./icmptun_server key\n");
    exit(1);
  }
  SHA256_Update(&sha256, argv[1], strlen(argv[1]));
#else //client
  server=0;
  if (argc<3) {
    printf("Usage: ./icmptun_client server_IP key\n");
    exit(1);
  }
  SHA256_Update(&sha256, argv[2], strlen(argv[2]));
#endif /*SERVER*/
  pthread_t t;
  srand(time(NULL));
  system("iptables -I INPUT -p icmp -j QUEUE");
  signal(SIGTERM, sigterm_handler);
  signal(SIGINT, sigterm_handler);
  if (server) printf("server\n");
  
  char tun_name[IFNAMSIZ];
  char *a_name;
  
  int i;
  unsigned char key[32];
  SHA256_Final(key, &sha256);
  printf("encryption key ");
  for (i=0; i<32; i++) printf("%02x",key[i]);
  printf("\n");
  ECRYPT_keysetup(&cipher_ctx,(const u8 *)key,256,64);

  strcpy(tun_name, "icmptun%d");
  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
  printf("device name %s, MTU %d\n",tun_name, 1500 - /*sizeof(struct mac)*/14 - sizeof(struct ip) - sizeof(struct icmphdr)-5);
  char cmd[100];
  sprintf(cmd,"ifconfig %s mtu %d", tun_name, 1500 - /*sizeof(struct mac)*/14 - sizeof(struct ip) - sizeof(struct icmphdr)-5);
  system(cmd);
  
  sock=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
  if (sock==-1) {
	printf("%s",strerror(errno));
	exit(1);
  }
  
  pthread_create(&t, NULL, &netfilter_thread, NULL);
  
  char buf[1600];
  int rv;
  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = 0;
  if (!server) {
    inet_pton(AF_INET, argv[1], &dest_addr.sin_addr);
    server_ip=ntohl(dest_addr.sin_addr.s_addr);
  }
  for (;;) {
    while ((rv = read(tun_fd, buf, sizeof(buf), 0)) && rv >= 0) {
	//packet to tun iface, send to network
	const size_t req_size=8;
	struct icmphdr req;
	if (server) req.type=0;
	else req.type=8;
	req.code=0;
	req.checksum=0;
	req.un.echo.id=htons(ICMP_ID);
	req.un.echo.sequence=htons(ICMP_SEQ);
	struct ip *iph = (struct ip *)buf;
	if (server) {
	  dest_addr.sin_addr.s_addr=htonl(get_dest(ntohl(iph->ip_dst.s_addr), &req.un.echo.id));
	  if (dest_addr.sin_addr.s_addr==0) {
	    printf("unknown destination address %u, discarding packet\n",ntohl(iph->ip_dst.s_addr));
	    continue;
	  }
	}
	printf("sent packet from %s to ", inet_ntoa(iph->ip_src));
	printf("%s\n", inet_ntoa(iph->ip_dst));
	char data[1600];
	memcpy(data,&req,req_size);
	ECRYPT_ctx x;
	memcpy(&x,&cipher_ctx,sizeof(ECRYPT_ctx));
	uint32_t iv=rand();
	long b=iv;
	ECRYPT_ivsetup(&x,(const u8 *)&b);
	memcpy(data+req_size, &iv, 4);
	char sum=iph->ip_sum%256;
	memcpy(data+req_size+4, &sum, 1);
	ECRYPT_encrypt_bytes(&x,buf,data+req_size+5,rv);
	req.checksum=checksum(data,req_size+rv+5); 
	memcpy(data,&req,req_size);
	if (sendto(sock,data,req_size+rv+5,0,(struct sockaddr*)&dest_addr,sizeof(dest_addr))==-1) {
	  printf("%s",strerror(errno));
	  exit(1);
	}
    }
  }
  return 0;
}