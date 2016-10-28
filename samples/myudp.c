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

typedef struct __USERS__
{
	struct sockaddr *addr;
	int sock;
} NET_SOCK;

static ikcpcb *kcp1;
static ikcpcb *kcp2;

static NET_SOCK net_sock;

static inline IUINT32 iclock()
{
	struct timeval time;
	gettimeofday(&time, NULL);
	IINT64 value =  ((IINT64)time.tv_sec) * 1000 + (time.tv_usec / 1000);
	return (IUINT32)(value & 0xfffffffful);
}

void * thread_ikcp_update(void *kcp)
{
	unsigned int msec = 0;
	ikcpcb *r_kcp = (ikcpcb *)kcp;
	while(1)
	{
		ikcp_update(r_kcp, iclock());
		// msec = ikcp_check(r_kcp,  iclock());
		// printf("msec=%u, iclock = %lu\n", msec, iclock());
		usleep(30*1000);
	}
}

int server(int port)
{
	struct sockaddr_in addr;

	pthread_t tid;

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

	while(1)
	{
		n = recvfrom(sock, buff, 1500, 0, (struct sockaddr*)&client_addr, &len);
		net_sock.addr = (struct sockaddr *)&client_addr;
		if(n > 0)
		{
			printf("server recv len =%d\n", n);
			ikcp_input(kcp1, buff, n);
			// if(n < 0)
			// {
			// 	perror("sendto");
			// 	break;
			// }
			// memset(buff, 0, sizeof(buff));

		}
		else
		{
			perror("recv");
			break;
		}
		// ikcp_update(kcp1, iclock());
		memset(buff, 0, sizeof(buff));
		n = ikcp_recv(kcp1, buff, 1400);
		printf("%s %u say: %s, len = %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buff, n);
		if(n < 0)
		{
			printf("ikcp recv failed\n");
			continue;
		}
		// n = sendto(sock, buff, n, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
		n = ikcp_send(kcp1, buff, n);


	}
	return 0;
}

int client(char *ip, int port)
{
	struct sockaddr_in addr;
	int sock;
	pthread_t tid;

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

	while(1)
	{
		// gets(buff);
		// scanf("%s", buff);
		strcpy(buff, "test hello world! test hello world!test hello world!test hello world!test hello world!");
		int n;
		// n = sendto(sock, buff, strlen(buff), 0, (struct sockaddr *)&addr, len);
		// if(n < 0)
		// {
		// 	perror("sendto");
		// 	close(sock);
		// 	break;
		// }
		n = ikcp_send(kcp2, buff, strlen(buff));
		printf("will send to msg = %s, n=%d, r_len=%lu\n", buff, n, strlen(buff));
		// ikcp_update(kcp2, iclock());
		// n = recvfrom(sock, buff, 1500, 0, (struct sockaddr *)&addr, &len);
		usleep(100*1000);
		continue;
		if(n > 0)
		{
			ikcp_input(kcp2, buff, n);
			printf("client received: %s\n", buff);
		}
		if (n == 0)
		{
			printf("server close\n");
			close(sock);
			break;
		}
		if(n < 0)
		{
			perror("recvfrom");
			close(sock);
			break;
		}
		memset(buff, 0, sizeof(buff));

		n = ikcp_recv(kcp2, buff, 1400);
		printf("client received: %s\n", buff);
	}
	return 0;
}


int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	NET_SOCK *net_sock = (NET_SOCK *)user;
	int ret;
	// printf("output sock = %d\n", net_sock->sock);
	// printf("output input len = %d\n", len);
	ret = sendto(net_sock->sock, buf, len, 0, net_sock->addr, sizeof(struct sockaddr));
	printf("send to output len = %d\n", ret);
	return ret;
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
		ikcp_setoutput(kcp1, udp_output);
		ikcp_wndsize(kcp1, 128, 128);
		ikcp_nodelay(kcp1, 0, 10, 0, 0);
		server(5000);
	}
	else if(!strcmp(argv[1], "client"))
	{
		kcp2 = ikcp_create(0x11223344, (void*)&net_sock);
		ikcp_setoutput(kcp2, udp_output);
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
