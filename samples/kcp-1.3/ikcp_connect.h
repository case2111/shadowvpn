#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
// #include <arpa/inet.h>
#include <sys/time.h>

#include "ikcp.h"
#include "list.h"

#define DEFAULT_HASH_SIZE 1024
#define MAX_MSG_SIZE      2000

#define DEBUG(fmt, args...) printf("%s line [%d] " fmt "\n", __FILE__, __LINE__,##args)

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
	int (*data_handle)(char *buf, int len, struct sockaddr_in *addr);
} CON_KCP;

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

typedef struct __SEND_MSG__
{
	unsigned int len;
	char *msg;
} SEND_MSG;

static inline IUINT32 iclock()
{
	struct timeval time;
	gettimeofday(&time, NULL);
 	long long unsigned int value =  ((IINT64)time.tv_sec) * 1000 + (time.tv_usec / 1000);
	// printf("time.tv_sec=%lu, time.tv_usec=%lu\n", time.tv_sec, time.tv_usec);
	return (IUINT32)(value & 0xfffffffful);
};


int init_ikcp_connect(CON_KCP *ikcp_c);

int set_ikcp_connect_uid(unsigned int u_id);

int hex_dump(void *msg, int msg_len);

unsigned int get_table_index(struct sockaddr_in *addr);

int table_ikcp_input(struct hlist_head *table_head, REV_MSG *rev_msg);

int send_ikcp_msg_handle_server(SEND_MSG *msg, struct sockaddr_in *addr);

int recv_ikcp_msg_handle_server(void);

int input_ikcp_msg_handle(REV_MSG *rev_msg);

int send_ikcp_msg_handle(SEND_MSG *msg, int flag);

int recv_ikcp_msg_handle(char *buffer);
