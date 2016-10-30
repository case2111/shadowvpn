#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "ikcp.h"
#include "list.h"


#define DEFAULT_HASH_SIZE 1024

#define DEBUG(fmt, args...) printf("at %s line [%d] " fmt, __FILE__, __LINE__,##args)
typedef struct __USERS__
{
	struct sockaddr *addr;
	int sock;
} NET_SOCK;

static ikcpcb *kcp1;
static ikcpcb *kcp2;

struct hlist_head c_table[DEFAULT_HASH_SIZE];
typedef struct __NODE__
{
	struct hlist_node node;
	unsigned int u_id;
	unsigned int timeval;
	struct sockaddr_in addr;
	ikcpcb *kcp;
} H_NODE;

typedef struct __PROTO_HEAD__
{
	short cmd;
	short u_id;
} MSG_HEAD;

static long unsigned int index = 0;

pthread_mutex_t mutext = PTHREAD_MUTEX_INITIALIZER;

static NET_SOCK net_sock;

int table_add_kcp(H_NODE *node, struct hlist_head table_head)
{
	char key[64] = {0};
	sprintf(key, "%u:%u", node->addr.sin_addr.s_addr, node->addr.sin_port);
	int hash = hash_func(key, DEFAULT_HASH_SIZE);
	H_NODE *t_node = (H_NODE *)malloc(sizeof(H_NODE));
	if(*t_node == NULL)
	{
		DEBUG("malloc failed\n");
		return -1;
	}
	memcpy(t_node, node, sizeof(H_NODE));
	t_node = time(NULL);
	hlist_add_head(t_node->node, table_head[hash]);
	return 0;
}

int table_maintain_kcp(struct hlist_head table_head)
{
	for(int i = 0; i < maxSize; i++)
	{
		if(!hlist_empty(table_head[i]))
		{
			struct hlist_node  n;
			H_NODE *kcp_node;
			unsigned int timestamp = time(NULL);
			hlist_for_each_entry_safe(kcp_node, n, head, node)
			{
				if((timestamp - kcp_node->timeval) > 15 * 60)
				{
					hlist_del(kcp_node->node);
				}
			}
		}
	}
}

int hex_dump(void *msg, int msg_len)
{
	int  i;
    char  hexstr[49], ascstr[17], buf[3];
    unsigned char  b, dumpstr = 0;
    char *pMsg = msg;
    memset (hexstr, ' ', 48); hexstr[48] = '\0';
    memset (ascstr, ' ', 16); ascstr[16] = '\0';

    printf ("\n");
    printf ("HEX                                              ASCII\n");

    for (i = 0; i < msg_len; i++)
    {
       b = pMsg[i];
       sprintf (buf, "%02x", b);
       hexstr[i%16*3]   = buf[0];
       hexstr[i%16*3+1] = buf[1];
       hexstr[i%16*3+2] = ' ';
       ascstr[i%16] = (b > 31 && b < 128) ? b : '.';
       if ((dumpstr = ((i + 1) % 16 == 0)) != 0)
       {
          printf ("%48s %16s\n", hexstr, ascstr);
          if (i < (msg_len - 1))
          {
             memset (hexstr, ' ', 48);
             memset (ascstr, ' ', 16);
          }
       }
    }
    if (!dumpstr)
    	printf ("%48s %16s\n", hexstr, ascstr);
    return 0;
}

void writelog(char *txt, ikcpcb *kcp, void *user)
{
	printf(txt);
	printf("\n");
}

static inline IUINT32 iclock()
{
	struct timeval time;
	gettimeofday(&time, NULL);
 	long long unsigned int value =  ((IINT64)time.tv_sec) * 1000 + (time.tv_usec / 1000);
	// printf("time.tv_sec=%lu, time.tv_usec=%lu\n", time.tv_sec, time.tv_usec);
	return (IUINT32)(value & 0xfffffffful);
}
int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	NET_SOCK *net_sock = (NET_SOCK *)user;
	int ret;
	// printf("output sock = %d\n", net_sock->sock);
	// printf("output input len = %d\n", len);
	ret = sendto(net_sock->sock, buf, len, 0, net_sock->addr, sizeof(struct sockaddr));
	printf("send to output len = %d\n", ret);
	hex_dump(buf, len);
	return ret;
}


void * thread_ikcp_update(void *kcp)
{
	unsigned int msec = 0;
	ikcpcb *r_kcp = (ikcpcb *)kcp;
	while(1)
	{
		unsigned int current = iclock();
		// printf("current = %lu\n", current);
		pthread_mutex_lock(&mutext);
		// printf("msec=%u, iclock = %lu, u_time=%u\n", msec, current, msec-current);
		ikcp_update(r_kcp, current);
		msec = ikcp_check(r_kcp,  current);
		pthread_mutex_unlock(&mutext);
		usleep((msec-current)*1000);
	}
}

void * kcp_recv_thread(void *kcp)
{
	char buffer[1500] = {0};
	int len = 0;
	ikcpcb *r_kcp = (ikcpcb *)kcp;
	for(;;)
	{
		len = ikcp_recv(r_kcp, buffer, 1000);
		if(len > 0)
			printf("receiv len= %d, txt=%s\n", len, buffer);
		else
			usleep(10*1000);
			// ikcp_send(r_kcp, buffer, len);
		memset(buffer, 0, sizeof(buffer));
		// if (len < 0)
		// 	sleep(1);
	}

}

int server(int port)
{
	struct sockaddr_in addr;

	pthread_t tid, rev_tid;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	int sock;
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		exit(1);
	}
	net_sock.sock = sock;
	if((bind(sock, (struct sockaddr *)&addr, sizeof(addr))) < 0)
	{
		perror("bind");
		exit(1);
	}
	printf("sock = %d\n", sock);
	char buff[1500]= {0};
	struct sockaddr_in client_addr;
	int len = sizeof(client_addr);
	int n;

	pthread_create(&tid, NULL, thread_ikcp_update, (void *)kcp1);
	// pthread_create(&rev_tid, NULL, kcp_recv_thread, (void *)kcp1);

	while(1)
	{
		// thread_ikcp_update(kcp1);
		n = recvfrom(sock, buff, 1500, 0, (struct sockaddr*)&client_addr, &len);
		net_sock.addr = (struct sockaddr *)&client_addr;
		if(n > 0)
		{
			// printf("server recv len =%d\n", n);
			printf("---%s %u say: %s, len = %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buff, n);
			hex_dump(buff, n);
			pthread_mutex_lock(&mutext);
				ikcp_input(kcp1, buff, n);
				memset(buff, 0, sizeof(buff));
				n = ikcp_recv(kcp1, buff, 1400);
				if(n > 0)
				{
					printf("%s %u say: %s, len = %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buff, n);
					ikcp_send(kcp1, buff, n);
				}
			pthread_mutex_unlock(&mutext);
			// if(n < 0)
			// {
			// 	perror("sendto");
			// 	break;
			// }
			// memset(buff, 0, sizeof(buff));

		}
		else
		{
			continue;
			perror("recv");
			break;
		}
		// ikcp_update(kcp1, iclock());
		// n = sendto(sock, buff, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
		// n = ikcp_send(kcp1, buff, n);


	}
	return 0;
}

int client(char *ip, int port)
{
	struct sockaddr_in addr;
	int sock;
	pthread_t tid, rev_tid;

	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	char buff[1500]= {0};
	int len = sizeof(addr);

	net_sock.addr = (struct sockaddr *)&addr;
	net_sock.sock = sock;
	printf("sock = %d\n", sock);

	pthread_create(&tid, NULL, thread_ikcp_update, (void *)kcp2);
	// pthread_create(&rev_tid, NULL, kcp_recv_thread, (void *)kcp2);

	unsigned int count = 0;
	while(1)
	{
		// gets(buff);
		// scanf("%s", buff);
		sprintf(buff, "number = %u test hello world! test hello world!test hello world!test hello world!test hello world!", count++);
		int n;
		// n = sendto(sock, buff, strlen(buff), 0, (struct sockaddr *)&addr, len);
		// if(n < 0)
		// {
		// 	perror("sendto");
		// 	close(sock);
		// 	break;
		// }
		// thread_ikcp_update(kcp2);
		pthread_mutex_lock(&mutext);
		n = ikcp_send(kcp2, buff, strlen(buff));
		pthread_mutex_unlock(&mutext);
		//printf("will send to msg = %s, n=%d, r_len=%lu\n", buff, n, strlen(buff));
		// ikcp_update(kcp2, iclock());
		usleep(1000*1000);
		n = recvfrom(sock, buff, 1500, 0, (struct sockaddr *)&addr, &len);
		// continue;
		if(n > 0)
		{
			pthread_mutex_lock(&mutext);
			ikcp_input(kcp2, buff, n);
			memset(buff, 0, sizeof(buff));
			n = ikcp_recv(kcp2, buff, 1400);
			pthread_mutex_unlock(&mutext);
			if (n > 0)
				printf("client received: %s\n", buff);
			// printf("client received: %s\n", buff);
		}
		else
		{
			printf("server close\n");
			close(sock);
			break;
		}
	}
	return 0;
}


int kcpinit()
{
	// kcp1 = ikcp_create(0x11223344, (void*)&net_sock);
	// kcp2 = ikcp_create(0x11223344, (void*)&net_sock);
	// ikcp_setoutput(kcp1, udp_output);
	// ikcp_setoutput(kcp2, udp_output);
	// ikcp_wndsize(kcp1, 128, 128);
	// ikcp_wndsize(kcp2, 128, 128);
	// ikcp_nodelay(kcp1, 0, 10, 0, 0);
	// ikcp_nodelay(kcp2, 0, 10, 0, 0);
	return 0;
}
int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf("Usage: %s server|client!\n", argv[0]);
		return -1;
	}
	kcpinit();
	if(!strcmp(argv[1], "server"))
	{
		kcp1 = ikcp_create(0x11223344, (void*)&net_sock);
		// ikcp_setoutput(kcp1, udp_output);
		kcp1->output = udp_output;
		// kcp1->writelog = writelog;
		ikcp_wndsize(kcp1, 128, 128);
		ikcp_nodelay(kcp1, 0, 10, 0, 0);
		server(5000);
	}
	else if(!strcmp(argv[1], "client"))
	{
		kcp2 = ikcp_create(0x11223344, (void*)&net_sock);
		// ikcp_setoutput(kcp2, udp_output);
		kcp2->output = udp_output;
		// kcp2->writelog = writelog;
		ikcp_wndsize(kcp2, 128, 128);
		ikcp_nodelay(kcp2, 0, 10, 0, 0);
		client("127.0.0.1", 5000);
	}
	else
	{
		printf("args error\n");
		exit(1);
	}
	return 0;

}
