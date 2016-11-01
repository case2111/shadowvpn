#include "ikcp_connect.h"

static CON_KCP ikcp_con;
static struct hlist_head c_table[DEFAULT_HASH_SIZE];
static pthread_mutex_t mutext = PTHREAD_MUTEX_INITIALIZER;


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

static int table_init(struct hlist_head *table_head)
{
	for(int i =0; i < DEFAULT_HASH_SIZE; i++)
	{
		INIT_LIST_HEAD(&table_head[i]);
	}
	return 0;
}

int init_ikcp_connect(CON_KCP *ikcp_c)
{
    ikcp_con.fd_socket = ikcp_c->fd_socket;
    ikcp_con.u_id = ikcp_c->u_id;
    memcpy(&ikcp_con.addr, &ikcp_c->addr, sizeof(struct sockaddr_in));
}

int init_ikcp_connect_server(CON_KCP *ikcp_c)
{
    ikcp_con.fd_socket = ikcp_c->fd_socket;
    ikcp_con.u_id = ikcp_c->u_id;
    memcpy(&ikcp_con.addr, &ikcp_c->addr, sizeof(struct sockaddr_in));
	table_init(&c_table);
	return 0;
}


int set_ikcp_connect_uid(unsigned int u_id)
{
    ikcp_con.u_id = u_id;
    return u_id;
}

unsigned int get_table_index(struct sockaddr_in *addr)
{
	char key[64] = {0};
	sprintf(key, "%u:%u", addr->sin_addr.s_addr, addr->sin_port);
	return hash_func(key, DEFAULT_HASH_SIZE);
}

static int cb_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	struct sockaddr_in *t_addr = (struct sockaddr_in *)user;
	int ret = sendto(ikcp_con.fd_socket, buf, len, 0, (struct sockaddr *)user, sizeof(struct sockaddr));
	DEBUG("send to output ip = %s port = %u ret = %d, msg_len = %d\n",inet_ntoa(t_addr->sin_addr) ,ntohs(t_addr->sin_port),ret, len);
	// hex_dump(buf, len);
	return ret;
}

static ikcpcb *create_kcp_instance(struct sockaddr_in *addr)
{
	int conv = get_table_index(addr);
	ikcpcb *t_kcp = ikcp_create(conv, (void*)addr);
	t_kcp->output = cb_output;
	ikcp_wndsize(t_kcp, 128, 128);
	ikcp_nodelay(t_kcp, 0, 10, 0, 0);
	return t_kcp;
}

static ikcpcb *create_kcp_instance_use_id(struct sockaddr_in *addr, unsigned int conv_id)
{
	ikcpcb *t_kcp = ikcp_create(conv_id, (void*)addr);
	t_kcp->output = cb_output;
	ikcp_wndsize(t_kcp, 128, 128);
	ikcp_nodelay(t_kcp, 0, 10, 0, 0);
	return t_kcp;
}

static int table_add_kcp(H_NODE *node, struct hlist_head *table_head)
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
					ret = sendto(ikcp_con.fd_socket, &echo_msg, sizeof(echo_msg), 0, (struct sockaddr *)rev_msg->addr, sizeof(struct sockaddr));
					DEBUG("recv hello, u_id = %u,send ok success\n", u_id);
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
				ikcp_send(kcp_node->kcp, tmp_buffer, len);
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
				DEBUG("receive ok success, hanshake over, u_id=%u\n", head->u_id);
				break;
			}
			case CON_RESET:
			{
				ikcp_release(ikcp_con.kcp);
				ikcp_con.kcp = NULL;
                DEBUG("receive reset success, release ikcp connection");
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

int send_connect_hello(int sock, struct sockaddr_in *addr, int flag)
{
    MSG_HEAD head;
    head.cmd = flag;
    head.u_id = 0;
    int ret = sendto(ikcp_con.fd_socket, &head, sizeof(head), 0, (struct sockaddr *)&ikcp_con.addr, sizeof(struct sockaddr));
    DEBUG("send hello succcess\n");
    return ret;
}

int send_ikcp_msg_handle(SEND_MSG *msg, int flag)
{
	int ret = 0;
	if(flag == CON_HELLO)
	{
		send_connect_hello(ikcp_con.fd_socket, &ikcp_con.addr, CON_HELLO);
	}
	else
	{
		if(ikcp_con.kcp)
		{
			ret = ikcp_send(ikcp_con.kcp, msg->msg, msg->len);
			DEBUG("send length = %d, msg len = %d", ret, msg->len);
		}
		else
		{
			DEBUG("kcp is NULL, send msg failed, will send hello msg\n");
            send_connect_hello(ikcp_con.fd_socket, &ikcp_con.addr, CON_HELLO);
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

int ikcp_connect_say_hello()
{
	for(int i = 0; i < 10; i++)
	{
		send_connect_hello(ikcp_con.fd_socket, &ikcp_con.addr, CON_HELLO);
		usleep(500*1000);
		char t_buffer[MAX_MSG_SIZE] = {0};
		int len = 0;
		len = recvfrom(ikcp_con.fd_socket, t_buffer, MAX_MSG_SIZE, MSG_DONTWAIT, (struct sockaddr *)&ikcp_con.addr, sizeof(struct sockaddr));
		if(len > 0 && len < 24)
		{
			MSG_HEAD *head = (MSG_HEAD *)t_buffer;
			switch(head->cmd)
			{
				case CON_HELLO:
				{
					break;
				}
				case CON_OK:
				{

					ikcp_con.u_id = head->u_id;
					ikcp_con.kcp = create_kcp_instance_use_id(&ikcp_con.addr, ikcp_con.u_id);
					DEBUG("receive ok success, hanshake over, u_id=%u\n", head->u_id);
					return CON_OK;
					break;
				}
				case CON_RESET:
				{
					ikcp_release(ikcp_con.kcp);
					ikcp_con.kcp = NULL;
					DEBUG("receive reset success, release ikcp connection");
					return CON_RESET;
				}
			}
		}
	}
}

void *thread_ikcp_update_server(void *arg)
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
				pthread_mutex_lock(&mutext);
				ikcp_update(kcp_node->kcp, current);
				pthread_mutex_unlock(&mutext);
			}
		}
		usleep(20*1000);
	}
}
