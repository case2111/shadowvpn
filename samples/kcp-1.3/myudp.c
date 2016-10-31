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
#define MAX_MSG_SIZE      2000


unsigned long int sec_id = 0;
int fd_sock;
enum
{
	CON_RESET = 100,
	CON_HELLO,
	CON_OK
};
typedef struct __CON_KCP__
{
	unsigned long int sec_id;
	int fd_socket;
	int u_id;
	ikcpcb *kcp;
	struct sockaddr addr;
} CON_KCP;

CON_KCP ikcp_con;

#define DEBUG(fmt, args...) printf("at %s line [%d] " fmt, __FILE__, __LINE__,##args)
typedef struct __USERS__
{
	struct sockaddr *addr;
	int sock;
} NET_SOCK;

static ikcpcb *kcp1;
static ikcpcb *kcp2;

struct hlist_head *c_table[DEFAULT_HASH_SIZE];
typedef struct __NODE__
{
	struct hlist_node node;
	unsigned int u_id;
	unsigned sec_num;
	unsigned int timeval;
	struct sockaddr_in addr;
	ikcpcb *kcp;
} H_NODE;

typedef struct __PROTO_HEAD__
{
	short cmd;
	short u_id;
} MSG_HEAD;

typedef struct __REV_MSG__
{
	unsigned int len;
	char *msg;
	struct sockaddr_in *addr;
} REV_MSG;

typedef struct __IKCP_MSG__
{
	struct sockaddr_in addr;
	unsigned int len;
	char *pMsg;
} IKCP_MSG;

typedef struct __SEND_MSG__
{
	unsigned int len;
	char *msg;
} SEND_MSG;

pthread_mutex_t mutext = PTHREAD_MUTEX_INITIALIZER;

static NET_SOCK net_sock;

unsigned int get_table_index(struct sockaddr_in *addr)
{
	char key[64] = {0};
	sprintf(key, "%u:%u", addr->sin_addr.s_addr, addr->sin_port);
	return hash_func(key, DEFAULT_HASH_SIZE);
}

void cb_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	int ret = sendto(fd_sock, buf, len, 0, (struct sockaddr *)user, sizeof(struct sockaddr));
	DEBUG("send to output len = %d\n", ret);
	// hex_dump(buf, len);
}

ikcpcb *create_kcp_instance(struct sockaddr_in *addr)
{
	int conv = get_table_index(addr);
	ikcpcb *t_kcp = ikcp_create(conv, (void*)addr);
	t_kcp->output = cb_output;
	ikcp_wndsize(t_kcp, 128, 128);
	ikcp_nodelay(t_kcp, 0, 10, 0, 0);
	return t_kcp;
}

ikcpcb *create_kcp_instance_use_id(struct sockaddr_in *addr, unsigned int conv_id)
{
	ikcpcb *t_kcp = ikcp_create(conv_id, (void*)addr);
	t_kcp->output = cb_output;
	ikcp_wndsize(t_kcp, 128, 128);
	ikcp_nodelay(t_kcp, 0, 10, 0, 0);
	return t_kcp;
}

int table_add_kcp(H_NODE *node, struct hlist_head *table_head)
{
	char key[64] = {0};
	sprintf(key, "%u:%u", node->addr.sin_addr.s_addr, node->addr.sin_port);
	unsigned int hash = hash_func(key, DEFAULT_HASH_SIZE);
	H_NODE *t_node = (H_NODE *)malloc(sizeof(H_NODE));
	if(t_node == NULL)
	{
		DEBUG("malloc failed\n");
		return -1;
	}
	memcpy(t_node, node, sizeof(H_NODE));
	INIT_HLIST_NODE(&t_node->node);
	t_node->kcp = create_kcp_instance(&t_node->addr);
	// t_node = time(NULL);
	hlist_add_head(&t_node->node, &table_head[hash]);
	return hash;
}
int table_init(struct hlist_head *table_head)
{
	for(int i =0; i < DEFAULT_HASH_SIZE; i++)
	{
		INIT_LIST_HEAD(&table_head[i]);
	}
	return 0;
}

int table_maintain_kcp(struct hlist_head *table_head)
{
	for(int i = 0; i < DEFAULT_HASH_SIZE; i++)
	{
		if(!hlist_empty(&table_head[i]))
		{
			struct hlist_node  *n;
			H_NODE *kcp_node;
			unsigned int timestamp = time(NULL);
			hlist_for_each_entry_safe(kcp_node, n, &table_head[i], node)
			{
				if((timestamp - kcp_node->timeval) > 15 * 60)
				{
					ikcp_release(kcp_node->kcp);
					hlist_del(&kcp_node->node);
					free(kcp_node);
				}
			}
		}
	}
}

int create_then_add_node(struct sockaddr_in *addr, struct hlist_head *table_head)
{
	H_NODE t_node;
	int ret = 0;
	memset(&t_node, 0, sizeof(t_node));
	memcpy(&t_node.addr, addr, sizeof(struct sockaddr_in));
	t_node.timeval = time(NULL);
	t_node.sec_num = sec_id;
	ret = table_add_kcp(&t_node, table_head);
	return ret;
}

int table_ikcp_input(struct hlist_head *table_head, REV_MSG *rev_msg)
{
	unsigned int hash = get_table_index(rev_msg->addr);
	struct hlist_node *n;
	H_NODE *kcp_node;
	hlist_for_each_entry_safe(kcp_node, n, &table_head[hash], node)
	{
		if(rev_msg->addr->sin_addr.s_addr == kcp_node->addr.sin_addr.s_addr && \
		   rev_msg->addr->sin_port == kcp_node->addr.sin_port)
		{
			ikcp_input(kcp_node->kcp, rev_msg->msg, rev_msg->len);
			break;
		}
	}

}
int input_ikcp_msg_handle_server(REV_MSG *rev_msg)
{
	int ret = -1;
	if(rev_msg->len < 24)
	{
		MSG_HEAD *head = (MSG_HEAD *)rev_msg->msg;
		switch(head->cmd)
		{
			case CON_HELLO:
			{
				unsigned int u_id = create_then_add_node(rev_msg->addr, c_table);
				if(u_id > 0)
				{
					MSG_HEAD echo_msg;
					echo_msg.u_id = u_id;
					echo_msg.cmd = CON_OK;
					ret = sendto(fd_sock, &echo_msg, sizeof(echo_msg), 0, (struct sockaddr *)rev_msg->addr, sizeof(struct sockaddr));
				}
				else
				{
					DEBUG("add node failed");
					ret = -1;
				}
				break;
			}
			case CON_RESET:
			{
				break;
			}
			case CON_OK:
			{
				break;
			}
			default:
			{
				DEBUG("error cmd %d\n", head->cmd);
				ret = -1;
			}
		}
	}
	else
	{
		unsigned int hash = get_table_index(rev_msg->addr);
		struct hlist_node *n;
		H_NODE *kcp_node;
		char msg_buffer[MAX_MSG_SIZE] = {0};
		hlist_for_each_entry_safe(kcp_node, n, &c_table[hash], node)
		{
			if(rev_msg->addr->sin_addr.s_addr == kcp_node->addr.sin_addr.s_addr && \
			   rev_msg->addr->sin_port == kcp_node->addr.sin_port)
		   {
			//    memcpy(msg_buffer, rev_msg->addr, sizeof(struct sockaddr_in));
			//    memcpy(&msg_buffer[sizeof(struct sockaddr_in)], rev_msg->msg, rev_msg->len);
			   ret = ikcp_input(kcp_node->kcp, rev_msg->msg, rev_msg->len);
			   break;
		   }
		}
	}
	return ret;
}

int send_ikcp_msg_handle_server(SEND_MSG *msg, struct sockaddr_in *addr)
{
	unsigned int hash = get_table_index(addr);
	struct hlist_node *n;
	H_NODE *kcp_node;
	int ret = -1;
	hlist_for_each_entry_safe(kcp_node, n, &c_table[hash], node)
	{
		if(addr->sin_addr.s_addr == kcp_node->addr.sin_addr.s_addr && \
		   addr->sin_port == kcp_node->addr.sin_port)
		{
			ret = ikcp_send(kcp_node->kcp, msg->msg, msg->len);
		}
	}
	return ret;
}


int recv_ikcp_msg_handle_server(void)
{
	char tmp_buffer[MAX_MSG_SIZE] = {0};
	struct sockaddr_in *tmp_addr = NULL;
	struct hlist_node *n;
	H_NODE *kcp_node;
	int len = 0;
	for(int i = 0; i< DEFAULT_HASH_SIZE; i++)
	{
		if(hlist_empty(&c_table[i]))
		{
			continue;
		}
		hlist_for_each_entry_safe(kcp_node, n, &c_table[i], node)
		{
			len = ikcp_recv(kcp_node->kcp, tmp_buffer, MAX_MSG_SIZE);
			if(len > 0)
			{
				DEBUG("%s %u say: %s, len = %d\n", inet_ntoa(kcp_node->addr.sin_addr), ntohs(kcp_node->addr.sin_port), tmp_buffer, len);
			}
		}
	}
	return len;
}

int input_ikcp_msg_handle(REV_MSG *rev_msg)
{
	char *msg = rev_msg->msg;
	unsigned int len = rev_msg->len;
	struct sockaddr_in *addr = rev_msg->addr;
	if(len < 24)
	{
		MSG_HEAD *head = (MSG_HEAD *)msg;
		switch(head->cmd)
		{
			case CON_HELLO:
			{
				break;
			}
			case CON_OK:
			{

				ikcp_con.u_id = head->u_id;
				ikcp_con.kcp = create_kcp_instance_use_id(addr, ikcp_con.u_id);
				break;
			}
			case CON_RESET:
			{
				ikcp_release(ikcp_con.kcp);
				ikcp_con.kcp = NULL;
			}
		}
	}
	else
	{
		ikcp_input(ikcp_con.kcp, rev_msg->msg, rev_msg->len);
		// table_ikcp_input(c_table, rev_msg);
	}
	return 0;
}

int send_ikcp_msg_handle(SEND_MSG *msg, int flag)
{
	int ret = 0;
	if(flag == CON_HELLO)
	{
		MSG_HEAD head;
		head.cmd = CON_HELLO;
		head.u_id = 0;
		ret = sendto(ikcp_con.fd_socket, &head, sizeof(head), 0, (struct sockaddr *)&ikcp_con.addr, sizeof(struct sockaddr));
	}
	else
	{
		if(ikcp_con.kcp)
		{
			ret = ikcp_send(ikcp_con.kcp, msg->msg, msg->len);
		}
		else
		{
			DEBUG("kcp is NULL, send msg failed\n");
			ret = -1;
		}
	}
	return ret;
}

int recv_ikcp_msg_handle(char *buffer)
{
	int ret = -1;
	if(ikcp_con.kcp)
	{
		ret = ikcp_recv(ikcp_con.kcp, buffer, MAX_MSG_SIZE);
	}
	else
	{
		DEBUG("kcp is NULL, receive msg failed\n");
		ret = -1;
	}
	return ret;
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
void *thread_ikcp_update_server(void)
{
	struct hlist_node *n;
	H_NODE *kcp_node;
	int len = 0;
	while(1)
	{
		unsigned int current = iclock();
		for(int i = 0; i< DEFAULT_HASH_SIZE; i++)
		{
			if(hlist_empty(&c_table[i]))
			{
				continue;
			}
			hlist_for_each_entry_safe(kcp_node, n, &c_table[i], node)
			{
				ikcp_update(kcp_node->kcp, current);
			}
		}
		usleep(20*1000);
	}
}

void * thread_ikcp_update(void *kcp)
{
	unsigned int msec = 0;
	ikcpcb *r_kcp = ikcp_con.kcp;
	while(1)
	{
		if(r_kcp == NULL)
		{
			usleep(200*1000);
			continue;
		}
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
	fd_sock = sock;
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

	pthread_create(&tid, NULL, thread_ikcp_update_server, NULL);
	REV_MSG rev_msg;
	while(1)
	{
		// thread_ikcp_update(kcp1);
		n = recvfrom(sock, buff, 1500, 0, (struct sockaddr*)&client_addr, &len);
		rev_msg.addr = &client_addr;
		rev_msg.msg = buff;
		rev_msg.len = n;
		net_sock.addr = (struct sockaddr *)&client_addr;
		if(n > 0)
		{
			input_ikcp_msg_handle_server(&rev_msg);
		}
		else
		{
			continue;
			perror("recv");
			break;
		}
		recv_ikcp_msg_handle_server();

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
	ikcp_con.fd_socket = sock;
	memcpy(&ikcp_con.addr, &addr, sizeof(addr));

	pthread_create(&tid, NULL, thread_ikcp_update, (void *)kcp2);
	// pthread_create(&rev_tid, NULL, kcp_recv_thread, (void *)kcp2);

	unsigned int count = 0;
	REV_MSG rev_msg;
	while(1)
	{
		// gets(buff);
		// scanf("%s", buff);
		sprintf(buff, "number = %u test hello world! test hello world!test hello world!test hello world!test hello world!", count++);
		int n;
		pthread_mutex_lock(&mutext);
		if(ikcp_con.kcp)
		{
			n = ikcp_send(ikcp_con.kcp, buff, strlen(buff));
		}
		else
		{
			MSG_HEAD hello_msg;
			hello_msg.cmd = CON_HELLO;
			hello_msg.u_id = 0;
			sendto(ikcp_con.fd_socket, &hello_msg, sizeof(hello_msg), 0, (struct sockaddr *)&ikcp_con.addr, sizeof(struct sockaddr));
		}
		pthread_mutex_unlock(&mutext);
		//printf("will send to msg = %s, n=%d, r_len=%lu\n", buff, n, strlen(buff));
		// ikcp_update(kcp2, iclock());
		usleep(1000*1000);
		n = recvfrom(sock, buff, 1500, 0, (struct sockaddr *)&addr, &len);
		rev_msg.msg = buff;
		rev_msg.len = n;
		rev_msg.addr = &addr;
		// continue;
		if(n > 0)
		{
			pthread_mutex_lock(&mutext);
			// ikcp_input(kcp2, buff, n);
			input_ikcp_msg_handle(&rev_msg);
			memset(buff, 0, sizeof(buff));
			// n = ikcp_recv(kcp2, buff, 1400);
			n = recv_ikcp_msg_handle(buff);
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
