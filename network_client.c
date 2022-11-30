#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/cdev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aby Sam Ross");

#define PORT 2325
#define SEND_INTERVAL 3000
#define LENGTH 49

char message[64] = "HOLA";

struct tcp_client_service
{
      int running;
      struct socket *socket;
      struct task_struct *send_thread;
      struct task_struct *recv_thread;
};

struct tcp_client_service *tcp_client;

int tcp_client_send_msg(void);

static int net_dev_open(struct inode *inode, struct file *file)
{
        pr_info("enter,%s\n", __func__);
	return 0;
}

static int net_dev_release(struct inode *inode, struct file *file)
{
        pr_info("enter,%s\n", __func__);
	return 0;
}

static ssize_t net_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
        pr_info("enter,%s,count=%d\n", __func__, count);
	return 0;
}

static ssize_t net_dev_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	char kbuf[64] = {0,};

	pr_info("enter,%s,count=%d\n", kbuf, count);

	if (copy_from_user(kbuf, buf, count))
		goto error;

	if (count < 64)
		kbuf[count] = 0;
	else
		kbuf[63] = 0;

	pr_info("strlen(kbuf)=%d,strlen(message)=%d,%d,%d\n"
		,strlen(kbuf)
		,strlen(message)
		,strncmp(kbuf, "run=off",7)
		,strncmp(kbuf, "run=on",6)
		);

	if (!strncmp(kbuf,"run=off",7)) {
		tcp_client->running = 0;
		pr_info("%s,tcp_client->running=%d\n"
			, __func__ ,tcp_client->running);
	} else if (!strncmp(kbuf,"run=on",6)) {
		tcp_client->running = 1;
		pr_info("%s,tcp_client->running=%d\n"
			, __func__ ,tcp_client->running);
	} else if (!strncmp(kbuf,"msg=",4)) {
		memcpy(message, &kbuf[4], strlen(kbuf)-4);
		tcp_client_send_msg();
	} else {
		pr_info("%s,%s\n", __func__, kbuf);
	}

error:
	pr_info("exit,%s,count=%d\n", kbuf, count);
	return count;
}

static long net_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
        pr_info("enter,%s\n", __func__);
	return 0;
}

struct file_operations net_dev_fops = {
	.open = net_dev_open,
	.release = net_dev_release,
	.read = net_dev_read,
	.write = net_dev_write,
	.unlocked_ioctl = net_dev_ioctl,
};


u32 create_address(u8 *ip)
{
        u32 addr = 0;
        int i;

        for(i=0; i<4; i++)
        {
                addr += ip[i];
                if(i==3)
                        break;
                addr <<= 8;
        }
        return addr;
}

int tcp_client_send(struct socket *sock, const char *buf, const size_t length,\
                unsigned long flags)
{
        struct msghdr msg;
        //struct iovec iov;
        struct kvec vec;
        int len, written = 0, left = length;
        mm_segment_t oldmm;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        /*
        msg.msg_iov     = &iov;
        msg.msg_iovlen  = 1;
        */
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags   = flags;

        oldmm = get_fs(); set_fs(KERNEL_DS);
repeat_send:
        /*
        msg.msg_iov->iov_len  = left;
        msg.msg_iov->iov_base = (char *)buf + written; 
        */
        vec.iov_len = left;
        vec.iov_base = (char *)buf + written;

        //len = sock_sendmsg(sock, &msg, left);
        len = kernel_sendmsg(sock, &msg, &vec, left, left);
        if((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) &&\
                                (len == -EAGAIN)))
                goto repeat_send;
        if(len > 0)
        {
                written += len;
                left -= len;
                if(left)
                        goto repeat_send;
        }
        set_fs(oldmm);

	pr_info("sending message : %s\n", buf);
        return written ? written:len;
}

int tcp_client_receive(struct socket *sock, char *str,\
                        unsigned long flags)
{
	int len;
        char buf[LENGTH+1];

        struct msghdr msg;
        struct kvec vec;
        int max_size = 50;

        msg.msg_name    = 0;
        msg.msg_namelen = 0;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags   = 0;

        vec.iov_len = max_size;
        vec.iov_base = buf;

	while(1) {
read_again:
		if (!tcp_client->socket) {
			pr_info("tcp_client->socket is not init yet\n");
			msleep(SEND_INTERVAL);
			goto read_again;
		}

		memset(&buf, 0, LENGTH+1);

		len = kernel_recvmsg(tcp_client->socket, &msg, &vec, max_size, max_size, 0);
		if (len == -EAGAIN || len == -ERESTARTSYS)
		{
			pr_info(" *** mtp | error while reading: %d | "
				"tcp_client_receive *** \n", len);
			goto read_again;
		}
		pr_info("the server says: %s\n", buf);
	}

        return len;
}

char *inet_ntoa(struct in_addr *in)
{
        char *str_ip = NULL;
        u_int32_t int_ip = 0;
        
        str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

        if(!str_ip)
                return NULL;
        else
                memset(str_ip, 0, 16);

        int_ip = in->s_addr;

        sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
                                 (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);

        return str_ip;
}


int tcp_client_connect(void)
{
	struct socket *conn_socket;
        struct sockaddr_in saddr;
        unsigned char destip[5] = {192,168,5,1,'\0'};
        char response[LENGTH+1];
        int ret = -1;

        DECLARE_WAIT_QUEUE_HEAD(recv_wait);

        ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
        if(ret < 0)
        {
                pr_info(" *** mtp | Error: %d while creating first socket. | "
                        "setup_connection *** \n", ret);
                goto err;
        }

	tcp_client->socket = conn_socket;

        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(PORT);
        saddr.sin_addr.s_addr = htonl(create_address(destip));

	pr_info("client ip = %s\n", inet_ntoa(&(saddr.sin_addr)));

        ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr\
                        , sizeof(saddr), O_RDWR);
        if(ret && (ret != -EINPROGRESS))
        {
                pr_info(" *** mtp | Error: %d while connecting using conn "
                        "socket. | setup_connection *** \n", ret);
                goto err;
        }
err:
        return ret;
}

int tcp_client_send_msg(void)
{
        char reply[LENGTH+1];
	struct socket *socket;

	socket = tcp_client->socket;

	memset(&reply, 0, LENGTH+1);
	strcat(reply, message);

	tcp_client_send(socket, reply, strlen(reply), MSG_DONTWAIT);
}

struct task_struct *thread;

static int __init network_client_init(void)
{
	static struct cdev net_cdev;
	struct class *net_class = NULL;
	struct device *dev;
	static unsigned int major;
	int ret = 0;
	dev_t cdev;

        pr_info("enter,%s\n", __func__);

        tcp_client = kmalloc(sizeof(struct tcp_client_service), GFP_KERNEL);
        memset(tcp_client, 0, sizeof(struct tcp_client_service));

	tcp_client_connect();

        tcp_client->recv_thread = kthread_run((void *)tcp_client_receive, NULL,\
                                        "client_recv");

	ret = alloc_chrdev_region(&cdev, 0, 8, "network_client");
	if (ret) {
		pr_info("alloc_chrdev_region() return error  = %d\n", ret);
		goto err1;
	}
	major = MAJOR(cdev);
	cdev_init(&net_cdev, &net_dev_fops);
	net_cdev.owner = THIS_MODULE;

	// add a char device to the system
	ret = cdev_add(&net_cdev, MKDEV(major, 0), 8);
	if (ret) {
		pr_info("cdev_add() return error = %d\n", ret);
		goto err2;
	}

	net_class = class_create(THIS_MODULE, "network_client");
	if (IS_ERR(net_class)) {
		pr_info("class_create() return error = %d\n", net_class);
		ret = net_class;
		goto err3;
	}

	dev = device_create(net_class, NULL, cdev,
			NULL, "network_client", 0);
	if (IS_ERR(dev)) {
		pr_info("device_create() return error = %d\n", ret);
		goto err4;
	}

        pr_info("exit,ret=%d\n",0);
	return 0;
err4:
	class_destroy(net_class);
err3:
	cdev_del(&net_cdev);
err2:
	unregister_chrdev_region(cdev, 8);
err1:
	return ret;
}

static void __exit network_client_exit(void)
{
        char response[LENGTH+1];
        char reply[LENGTH+1];

	struct socket *conn_socket = tcp_client->socket;

        DECLARE_WAIT_QUEUE_HEAD(exit_wait);

        memset(&reply, 0, LENGTH+1);
        strcat(reply, "ADIOS"); 
        tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

        //while(1)
        //{
                /*
                tcp_client_receive(conn_socket, response);
                add_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait)
                */
         wait_event_timeout(exit_wait,\
                         !skb_queue_empty(&conn_socket->sk->sk_receive_queue),\
                                                                        5*HZ);
        if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))
        {
                memset(&response, 0, LENGTH+1);
                tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
                //remove_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait);
        }

        //}

        if(conn_socket != NULL)
        {
                sock_release(conn_socket);
        }
        pr_info(" *** mtp | network client exiting | network_client_exit *** \n");
}

module_init(network_client_init)
module_exit(network_client_exit)
