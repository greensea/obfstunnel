#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "obfstunnel.h"
#include "udpsession.h"

/// Configuration variables to obfs core
static int otcfg_side = 0;
static int otcfg_proto = SOCK_STREAM;
static unsigned short int otcfg_client_port;
static unsigned short int otcfg_server_port;
static unsigned short int otcfg_target_port;
static char otcfg_target_host[1024] = {0};
static int otcfg_udp_ttl = 120;
int otcfg_log_level = OT_LOGLEVEL_INFO;


/// Function pointers to obfs methods
void (*obfsem_encode)(void*, size_t, void**, size_t*) = NULL;
void (*obfsem_decode)(void*, size_t, void**, size_t*) = NULL;
int (*obfsem_init)(const char*) = NULL;
char* (*obfsem_version)(void) = NULL;
char* obfsem_name = "(Unknown)";


/// Configuration variables to obfs methods
int obfsvar_random_padlen = 0;
int obfsvar_random_maxlen = INT_MAX;
char* obfsvar_random_salt = "";

uint8_t obfsvar_xor_mask = 0xff;


int obfsem_random_init(const char* opt) {
	char* str;
	char* arg;
	char* saveptr = NULL;
	
	if (opt == NULL) {
		return -1;
	}
	
	OT_LOGI("obfs random method version 0.1\n");
	OT_LOGI("obfs random method acceptable parameters:\n");
	OT_LOGI("\tpadlen=[number] The max length of random bytes could be pad to a packet\n");
	OT_LOGI("\tmaxlen=[number] If length of padded packet is larger than maxlen, packet will be truncate to maxlen\n");
	OT_LOGI("\tsalt=[string] Any string you like, use to randomize traffic. the longer the better.\n");
	str = strdup(opt);
	
	/// Parse parameters
	arg = strtok_r(str, ",", &saveptr);
	do {
		char* subarg;
		char* subsaveptr = NULL;

		subarg = strtok_r(arg, "=", &subsaveptr);
		
		if (strcasecmp(subarg, "padlen") == 0) {
			obfsvar_random_padlen = atoi(strtok_r(NULL, "=", &subsaveptr));
		}
		else if (strcasecmp(subarg, "maxlen") == 0) {
			obfsvar_random_maxlen = atoi(strtok_r(NULL, "=", &subsaveptr));
		}
		else if (strcasecmp(subarg, "salt") == 0) {
			obfsvar_random_salt = strdup(strtok_r(NULL, "=", &subsaveptr));
		}
		else if (strcasecmp(subarg, "random") == 0) {
			/// Nothing to do
		}
		else {
			OT_LOGW("Unknown method option `%s'\n", subarg);
		}
	} while ((arg = strtok_r(NULL, ",", &saveptr)) != NULL);
	
	free(str);
	
	OT_LOGI("obfs random method: padlen = %d\n", obfsvar_random_padlen);
	OT_LOGI("obfs random method: maxlen = %d\n", obfsvar_random_maxlen);
	OT_LOGI("obfs random method: salt = `%s'\n", obfsvar_random_salt);

	
	return 0;
}

/**
 * obfsem is short for OBFuScate Encode Method
 * 
 * Randomize data and packet length.
 * 
 * Input: [payload]
 * Output: [initial vector][payload length][XORed payload][random data]
 *           4 bytes           2 bytes     same as payload  random bytes
 */
void obfsem_randomize_encode(void* in, size_t insiz, void** out, size_t* outsiz) {
	static void* buf = NULL;
	static uint32_t iv;
	uint16_t* paklen;
	int i, padlen, saltlen;
	int seed = 1;	/// Random number seed for srand()
	
	if (seed == 1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		seed = tv.tv_usec;
		srand(seed);
	}
	
	saltlen = strlen(obfsvar_random_salt);
	
	if (obfsvar_random_padlen > 0) {
		padlen = rand() % obfsvar_random_padlen;	/// Pad max to _padlen_ bytes to packet
		padlen = (insiz + padlen + 4 + 2 <= obfsvar_random_maxlen) ? padlen : (obfsvar_random_maxlen - insiz - 4 -2);	/// But packet should not larger than _maxlen_
	}
	else {
		padlen = 0;
	}
	if (padlen < 0) {
		padlen = 0;
	}
	
	iv = rand();
	
	*outsiz = 4 + 2 + insiz + padlen;
	
	if (buf != NULL) {
		free(buf);
		buf = NULL;
	}
	buf = malloc(*outsiz);
	
	paklen = buf + 4;	/// Point to payload length
	
	memcpy(buf, &iv, 4);	/// Fill initial vector
	*paklen = htons(insiz);	/// Fill payload length
	
	/// Encode payload length
	((unsigned char*)paklen)[0] ^= ((unsigned char*)&iv)[0];
	((unsigned char*)paklen)[1] ^= ((unsigned char*)&iv)[1];
	
	/// Fill payload
	for (i = 0; i < insiz; i++) {
		((unsigned char*)buf)[4 + 2 + i] = ((unsigned char*)&iv)[i % 4] ^ ((unsigned char*)in)[i];
		((unsigned char*)buf)[4 + 2 + i] ^= (unsigned char)obfsvar_random_salt[i % 4];
	}
	/// Fill random data
	for (i = 0; i < padlen; i++) {
		((unsigned char*)buf)[4 + 2 + insiz + i] = rand() % 256;
	}
	
	*out = buf;
}

void obfsem_randomize_decode(void* in, size_t insiz, void** out, size_t* outsiz) {
	static void* buf = NULL;
	int i, saltlen;
	uint16_t paklen;
	
	saltlen = strlen(obfsvar_random_salt);
	
	/// Read payload length and decode it
	memcpy(&paklen, in + 4, 2);
	((unsigned char*)&paklen)[0] ^= ((unsigned char*)in)[0];
	((unsigned char*)&paklen)[1] ^= ((unsigned char*)in)[1];
	
	
	*outsiz = ntohs(paklen);
	
	if (buf != NULL) {
		free(buf);
		buf = NULL;
	}
	buf = malloc(*outsiz);
	
	/// Decode
	for (i = 0; i < *outsiz; i++) {
		*(unsigned char*)(buf + i) = *(unsigned char*)(in + (i % 4)) ^ *(unsigned char*)(in + 4 + 2 + i);
		*(unsigned char*)(buf + i) ^= (unsigned char)obfsvar_random_salt[i % 4];
	}

	*out = buf;
}

int obfsem_xor_init(const char* opt) {
	char* str;
	char* arg;
	char* subarg;
	
	if (opt == NULL) {
		return -1;
	}
	
	
	OT_LOGI("obfs method xor version 0.1\n");
	OT_LOGI("obfs method xor acceptable parameters:\n");
	OT_LOGI("\tmask=<number>\n");
	OT_LOGI("\tExample: -o xor,mask=255\t//This will make every byte XOR with 0xff\n");
	
	obfsvar_xor_mask = 0xff;
	
	str = strdup(opt);
	
	arg = strtok(str, ",");
	arg = strtok(NULL, ",");
	if (arg != NULL) {
		subarg = strtok(arg, "=");
		subarg = strtok(NULL, "=");
		if (subarg != NULL) {
			obfsvar_xor_mask = (unsigned int)atoi(subarg);
		}
	}
	
	OT_LOGI("obfs method xor: Use 0x%02X as XOR mask\n", obfsvar_xor_mask);
	
	free(str);
	
	return 0;
}

/**
 * XOR traffic with 0xFF in byte.
 */
void obfsem_xor_encode(void* in, size_t insiz, void** out, size_t* outsiz) {
	static unsigned char* buf = NULL;
	int i;
	
	/// Free buf if needed. buf may be malloced on last call to this function
	if (buf != NULL) {
		free(buf);
	}
	
	buf = malloc(insiz);
	
	for (i = 0; i < insiz; i++) {
		buf[i] = *(unsigned char*)(in + i) ^ obfsvar_xor_mask;
	}
	
	*out = buf;
	*outsiz = insiz;
}
/**
 * XOR traffic with 0xFF in byte.
 */
void obfsem_xor_decode(void* in, size_t insiz, void** out, size_t* outsiz) {
	/// Do XOR again will get the origin content
	obfsem_xor_encode(in, insiz, out, outsiz);
}


/**
 * Do not encode anything, just keep the origin.
 * This is the encode method for transparent tunneling.
 * If no encode method is specify, this method will be used as default.
 */
void obfsem_keep_encode(void* in, size_t insiz, void** out, size_t* outsiz) {
	static void* buf = NULL;
	
	if (buf != NULL) {
		free(buf);
	}
	
	buf = malloc(insiz);
	memcpy(buf, in, insiz);
	
	*outsiz = insiz;
	*out = buf;
}

/**
 * Do not decode anything, just keep the origin.
 * This is the decode method for transparent tunneling.
 * If no decode method is specify, this method will be used as default.
 */
void obfsem_keep_decode(void* in, size_t insiz, void** out, size_t* outsiz) {
	obfsem_keep_encode(in, insiz, out, outsiz);
}


/**
 * 解析域名
 * 
 * @param const char*	域名
 * @param int*	错误值，可以为空
 * @return char*	IP 地址，若解析失败返回 NULL
 */
char* dns_query(const char* node, int* _err)
{
	int s;
	int __err;
	char* ip = NULL;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	if (_err == NULL) {
		_err = &__err;
	}

	if (node == NULL) {
		OT_LOGD("Invalid argument: node == NULL\n");
		*_err = 3;
		return NULL;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4 only */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = AI_CANONNAME;	/* Lookup name */
	hints.ai_protocol = 0;          /* Any protocol */

	/// 必须传一个端口，所以这里使用 HTTP 端口
	s = getaddrinfo(node, NULL, &hints, &result);
	if (s != 0) {
		/// 应该是没有找到域名记录
		OT_LOGD("getaddrinfo: %s\n", gai_strerror(s));
		*_err = 1;
		return NULL;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		printf("Get address: %s, carnonname: %s\n", inet_ntoa(((struct sockaddr_in*)rp->ai_addr)->sin_addr), rp->ai_canonname);
		
		ip = inet_ntoa(((struct sockaddr_in*)rp->ai_addr)->sin_addr);
		break;	/// 只取第一个结果
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		*_err = 2;
		return NULL;
	}
	else {
		*_err = 0;
		return ip;
	}
}

/**
 * 接收指定长度的数据
 * 
 * @param	int	文件的 fd 号
 * @param	void*	接收内容的缓冲区
 * @param	size_t	欲接收的长度
 * @param	int	传递给 recv 的 flag 参数
 * @return	ssize_t	接收到的长度，如果成功，返回大小和 buflen 一样
 */
ssize_t recvlen(int fd, void* buf, size_t buflen, int flag) {
	int readb = 0;
	int ret;
	
	while (readb < buflen) {
		ret = recv(fd, buf + readb, buflen - readb, flag);

		if (ret < 0) {
			switch (errno) {
				case EAGAIN:
				case EINTR:
					continue;
					break;
					
				default:
					OT_LOGE("recv() error while reading: %s\n", strerror(errno));
					return ret;
					break;
			}
		}
		else if (ret == 0) {
			OT_LOGW("remote peer disconnected\n");
			return 0;
		}
		else {
			readb += ret;
		}
	}
	
	return readb;
	
}

/**
 * 数据转发过程，SERVER 端
 * 由 ot_tunneling_tcp 函数调用
 */
int ot_tunneling_tcp_server(int lfd, int tfd) {
	unsigned char sndbuf[OT_PACKET_SIZE];
	unsigned char rcvbuf[65535];	/// Max obfstunnel packet size
	uint16_t paklen;
	int readb, writeb;
	int nfd;
	fd_set rfds, initrfds;
	int ret;
	void* outbuf;
	size_t outsiz;
	
	nfd = (lfd > tfd) ? lfd : tfd;
	nfd += 1;	/// select() ask nfd be the largest numbered fd, plus 1
	
	FD_ZERO(&initrfds);
	FD_SET(lfd, &initrfds);
	FD_SET(tfd, &initrfds);
	
	while (1) {
		rfds = initrfds;

		ret = select(nfd, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			OT_LOGE("select() error: %s\n", strerror(errno));
			return -1;
		}
		else if (ret == 0) {
			OT_LOGW("select() timed out\n");
			continue;
		}
		
		//OT_LOGD("%d fds changed\n", ret);

		/// 转发本地到远程
		if (FD_ISSET(lfd, &rfds)) {
			/// 读取包长度
			readb = recvlen(lfd, &paklen, sizeof(paklen), 0);
			
			if (readb != sizeof(paklen)) {
				OT_LOGE("recvlen() = %d, error on reading packet header: %s\n", readb, strerror(errno));
				return -1;
			}
			OT_LOGD("recvd paklen from client = %d\n", ntohs(paklen));
			paklen = ntohs(paklen);
			
			/// 读取数据
			assert(paklen <= sizeof(rcvbuf));
			readb = recvlen(lfd, rcvbuf, paklen, 0);
			
			if (readb != paklen) {
				OT_LOGE("recvlen() = %d, error on reading payload: %s\n", readb, strerror(errno));
				return -2;
			}
						
			if (readb < 0) {
				OT_LOGE("recv() error while reading local fd: %s\n", strerror(errno));
				return -2;
			}
			else if (readb == 0) {
				OT_LOGW("remote peer on local fd disconnected\n");
				return -3;
			}
			

			obfsem_decode(rcvbuf, readb, &outbuf, &outsiz);
			
			OT_LOGD("local -> target readb = %d bytes, outsiz = %d bytes\n", readb, outsiz);
			
			//writeb = write(STDOUT_FILENO, buf, readb);
			//writeb = send(tfd, buf, readb, 0);
			writeb = send(tfd, outbuf, outsiz, 0);
		}
		
		/// 转发远程到本地（即转发到客户端连接上）
		if (FD_ISSET(tfd, &rfds)) {
			readb = recv(tfd, sndbuf, sizeof(sndbuf), 0);
			
			if (readb < 0) {
				switch (errno) {
					case EAGAIN:
					case EINTR:
						continue;
						break;
						
					default:
						OT_LOGE("recv() error on target fd: %s\n", strerror(errno));
						return -4;
						break;
				}
			}
			else if (readb == 0) {
				OT_LOGW("remote peer on target fd disconnected\n");
				return -5;
			}
			
			obfsem_encode(sndbuf, readb, &outbuf, &outsiz);
			
			/// 转发数据
			OT_LOGD("remote --> local readb = %d bytes, outsiz = %d bytes\n", readb, outsiz);
			
			//writeb = write(STDOUT_FILENO, buf, readb);
			paklen = outsiz;
			assert(outsiz == paklen);
			paklen = htons(paklen);
			writeb = send(lfd, &paklen, sizeof(paklen), 0);
			writeb = send(lfd, outbuf, outsiz, 0);
//			writeb = send(lfd, buf, readb, 0);
		}
	
	}
	
	return 0;
}


/**
 * 数据转发过程，CLIENT 端
 * 由 ot_tunneling_tcp 函数调用
 */
int ot_tunneling_tcp_client(int lfd, int tfd) {
	unsigned char sndbuf[OT_PACKET_SIZE];
	unsigned char rcvbuf[65535];	/// Max obfstunnel packet size
	uint16_t paklen;
	int readb, writeb;
	int nfd;
	fd_set rfds, initrfds;
	int ret;
	void* outbuf;
	size_t outsiz;
	
	nfd = (lfd > tfd) ? lfd : tfd;
	nfd += 1;	/// select() ask nfd be the largest numbered fd, plus 1
		
	FD_ZERO(&initrfds);
	FD_SET(lfd, &initrfds);
	FD_SET(tfd, &initrfds);
		
	while (1) {
		rfds = initrfds;

		ret = select(nfd, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			OT_LOGE("select() error: %s\n", strerror(errno));
			return -1;
		}
		else if (ret == 0) {
			OT_LOGW("select() timed out\n");
			continue;
		}
		
		//OT_LOGD("%d fds changed\n", ret);

		/// 转发服务器到本地
		if (FD_ISSET(tfd, &rfds)) {
			/// 读取包长度
			readb = recvlen(tfd, &paklen, sizeof(paklen), 0);
			
			if (readb != sizeof(paklen)) {
				OT_LOGE("recvlen() = %d, error on reading packet header: %s\n", readb, strerror(errno));
				return -1;
			}
			
			paklen = ntohs(paklen);
			OT_LOGD("recved paklen from server = %d\n", paklen);
			
			/// 读取数据
			assert(paklen <= sizeof(rcvbuf));
			readb = recvlen(tfd, rcvbuf, paklen, 0);
			
			if (readb != paklen) {
				OT_LOGE("recvlen() = %d, error on reading payload: %s\n", readb, strerror(errno));
				return -2;
			}
			
			if (readb < 0) {
				OT_LOGE("recv() error while reading server fd: %s\n", strerror(errno));
				return -2;
			}
			else if (readb == 0) {
				OT_LOGW("remote peer on local fd disconnected\n");
				return -3;
			}
			
			OT_LOGD("server --> local readb = %d bytes\n", readb);

			obfsem_decode(rcvbuf, readb, &outbuf, &outsiz);
			
			//writeb = write(STDOUT_FILENO, buf, readb);
			//writeb = send(tfd, buf, readb, 0);
			writeb = send(lfd, outbuf, outsiz, 0);
			OT_LOGD("local --> user writeb =  %d bytes\n", writeb);
		}
		
		/// 转本地到服务器
		if (FD_ISSET(lfd, &rfds)) {
			readb = recv(lfd, sndbuf, sizeof(sndbuf), 0);
			
			if (readb < 0) {
				switch (errno) {
					case EAGAIN:
					case EINTR:
						continue;
						break;
						
					default:
						OT_LOGE("recv() error on local fd: %s\n", strerror(errno));
						return -4;
						break;
				}
			}
			else if (readb == 0) {
				OT_LOGW("remote peer on local fd disconnected\n");
				return -5;
			}
			
			obfsem_encode(sndbuf, readb, &outbuf, &outsiz);
			
			/// 转发数据
			OT_LOGD("local --> server readb = %d bytes, outsiz = %d bytes\n", readb, outsiz);
			
			//writeb = write(STDOUT_FILENO, buf, readb);
			paklen = outsiz;
			assert(paklen == outsiz);
			paklen = htons(paklen);
			writeb = send(tfd, &paklen, sizeof(paklen), 0);
			writeb = send(tfd, outbuf, outsiz, 0);
//			writeb = send(lfd, buf, readb, 0);
		}
	
	}
	
	return 0;
}


/**
 * 数据转发过程
 * CLIENT <--> CLIENT_MODE <==obfs==> SERVER_MODE <--> TARGET_HOST
 * TCP 模式下，所有数据包都会附加一个2字节长度的头，以区分数据包边界
 * -------------------------
 * |  length  |   payload  |
 * -------------------------                      
 *  <-- 2B --> <---flex--->
 * 
 * @param int	本地网络连接（SERVER 模式：与客户端的连接；CLIENT 模式：本地监听端口的连接）
 * @param int	远程网络连接（SERVER 模式：与目标主机的连接；CLIENT 模式：与服务器的连接）
 * @return int	成功返回 0，失败返回其他值
 */
int ot_tunneling_tcp(int lfd, int tfd) {
	switch (otcfg_side) {
		case OT_SIDE_SERVER:
			return ot_tunneling_tcp_server(lfd, tfd);
			break;
			
		case OT_SIDE_CLIENT:
			return ot_tunneling_tcp_client(lfd, tfd);
			break;
			
		default:
			break;
	}
	
	return 0;
}

int ot_accept_client(int fd) {
	int tfd;
	int ret;
	int flags;
	struct sockaddr_in taddr;
	
	taddr.sin_family = AF_INET;
	taddr.sin_port = htons(otcfg_target_port);
	ret = inet_aton(otcfg_target_host, &taddr.sin_addr);
	if (ret == 0) {
		char* ipstr = NULL;

		OT_LOGI("Resolving domain name `%s'\n", otcfg_target_host);
		
		ipstr = dns_query(otcfg_target_host, NULL);
		if (ipstr == NULL) {
			OT_LOGW("Could not resolve domain `%s'\n", otcfg_target_host);
			shutdown(fd, SHUT_RDWR);
			close(fd); 
			exit(-3);
		}
		else {
			OT_LOGI("Resolved domain: %s --> %s\n", otcfg_target_host, ipstr);
		}
		
		inet_aton(ipstr, &taddr.sin_addr);
	}
	
	
	// 连接到目标服务器
	tfd = socket(AF_INET, SOCK_STREAM, 0);
	if (tfd <= 0) {
		perror("sub socket");
		shutdown(fd, SHUT_RDWR);
		close(fd); 
		exit(-1);
	}
	
	OT_LOGI("Connecting to %s:%d\n", inet_ntoa(taddr.sin_addr), ntohs(taddr.sin_port));
	ret = connect(tfd, (struct sockaddr*)&taddr, sizeof(taddr));
	if (ret < 0) {
		perror("sub connect");
		shutdown(fd, SHUT_RDWR);
		close(fd);
		close(tfd);
		exit(-2);
	}
	
	flags = fcntl(tfd, F_GETFL, 0);
	/*
	ret = fcntl(tfd, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		perror("sub fcntl");
		shutdown(fd, SHUT_RDWR);
		shutdown(tfd, SHUT_RDWR);
		close(tfd);
		close(fd);
		exit(-1);
	}
	*/
	
	printf("Connected to target host %s:%d\n", otcfg_target_host, otcfg_target_port);
	
	/// 转发
	ot_tunneling_tcp(fd, tfd);
	
	shutdown(fd, SHUT_RDWR);
	shutdown(tfd, SHUT_RDWR);
	
	close(tfd);
	
	return 0;
}

int ot_listen_tcp(int fsd, int lisport) {
	int ret;
	int afd;
	struct sockaddr_in raddr;
	socklen_t raddrlen;
	
	ret = listen(fsd, 1);
	if (ret < 0) {
		perror("listen");
		exit(-3);
	}
	
	while (1) {
		//int flags;
		
		printf("Waiting incoming connections on port %d\n", lisport);
		
		raddrlen = sizeof(raddr);
		afd = accept(fsd, (struct sockaddr*)&raddr, &raddrlen);
		
		/*flags = fcntl(afd, F_GETFL, 0);
		ret = fcntl(afd, F_SETFL, flags | O_NONBLOCK);
		if (ret == -1) {
			perror("fcntl");
			close(afd);
			close(fsd);
			exit(-1);
		}*/
		
		if (afd != -1) {
			OT_LOGI("Connection from %s:%d established\n", inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
		}
		else {
			switch (errno) {
				case EINTR:
				case EAGAIN:
					continue;
					break;
				default:
					OT_LOGE("accept() error: %s\n", strerror(errno));
					exit(-1);
					break;
			}
		}
		
		if (fork() == 0) {
			if (fork() == 0) {
				ot_accept_client(afd);
				
				close(afd);
				printf("Connection from %s:%d disconnected\n", inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
				
				exit(0);
			}
			else {
				exit(0);
			}
		}
		else {
			wait(NULL);
			close(afd);
		}
	}
	
	close(fsd);
	
	return 0;
}

/**
 * Convert IP address or domain name and port into struct sockaddr_in
 */
struct sockaddr_in addr_parse(char* ip, int port) {
	struct sockaddr_in taddr;
	int ret;
	
	memset(&taddr, 0x00, sizeof(taddr));
	
	taddr.sin_family = AF_INET;
	taddr.sin_port = htons(otcfg_target_port);
	ret = inet_aton(ip, &taddr.sin_addr);
	if (ret == 0) {
		char* ipstr = NULL;

		OT_LOGI("Resolving domain name `%s'\n", otcfg_target_host);
		
		ipstr = dns_query(ip, NULL);
		if (ipstr == NULL) {
			OT_LOGE("Could not resolve domain `%s'\n", otcfg_target_host);
			return taddr;
		}
		else {
			OT_LOGI("Resolved domain: %s --> %s\n", otcfg_target_host, ipstr);
		}
		
		inet_aton(ipstr, &taddr.sin_addr);
	}

	return taddr;
}

int ot_tunneling_udp(int lfd) {
	fd_set initfds;
	fd_set rfds;
	int fd, nfds, ret, rcvlen;
	size_t buflen;
	unsigned char rcvbuf[65535];	/// Maxinum of UDP packet size is 65535
	void* buf;
	udp_session_t* s;
	struct sockaddr_in caddr;	/// Client address
	struct sockaddr_in raddr;	/// Remote host address
	socklen_t raddr_len;
	socklen_t caddr_len;
	time_t curtime, gctime;
	struct timeval to;
	
	gctime = time(NULL);
	
	/// 1. Waiting client data or server data
	/// 2. Tunneling data
	/// 	2.1 Got cilent data
	/// 		2.1.1 Client is newly connected
	/// 			2.1.1.1 Create an UDP session for it, then
	/// 			2.1.1.2 Add relate fd to fdset, then
	/// 			2.1.1.3 Tunneling data.
	/// 		2.1.2 Client is exists in UDP session, just tunneling data
	/// 	2.2 Got server data, get the related client addr, then tunneling data
	
	FD_ZERO(&initfds);
	FD_SET(lfd, &initfds);
	nfds = lfd;
	
	while (1) {
		/// Cleaning up timed out UDP sessions
		if (time(NULL) - gctime > otcfg_udp_ttl) {
			udps_cleanup(otcfg_udp_ttl);
			gctime = time(NULL);

			///Rebuild fdset
			nfds = udps_fdset(&initfds);
			FD_SET(lfd, &initfds);
			if (lfd > nfds) {
				nfds = lfd;
			}
		}

		rfds = initfds;
		to.tv_sec = otcfg_udp_ttl + 1;
		to.tv_usec = 0;
		
		ret = select(nfds + 1, &rfds, NULL, NULL, &to);
		if (ret == -1) {
			OT_LOGE("select() error: %s\n", strerror(errno));
			return -1;
		}
		else if (ret == 0) {
			OT_LOGD("select() timed out\n");
			
			udps_cleanup(otcfg_udp_ttl);
			gctime = time(NULL);
			
			///Rebuild fdset
			nfds = udps_fdset(&initfds);
			FD_SET(lfd, &initfds);
			if (lfd > nfds) {
				nfds = lfd;
			}
			
			continue;
		}
		
		curtime = time(NULL);
		
		if (FD_ISSET(lfd, &rfds)) {
			/// 在监听端口收到数据
			memset(&caddr, 0x00, sizeof(caddr));
			caddr_len = sizeof(caddr);
			rcvlen = recvfrom(lfd, rcvbuf, sizeof(rcvbuf), 0, (struct sockaddr*)&caddr, &caddr_len);
			if (rcvlen > 0) {
				OT_LOGD("Recived %d bytes from client %s:%d\n", rcvlen, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
			}
			else if (rcvlen == 0) {
				OT_LOGD("Client listen connection broken\n");
				return 0;
			}
			else {
				OT_LOGE("recvfrom() fail: %s\n", strerror(errno));
				continue;
			}
			
			s = udps_search_byladdr(caddr);
			if (s == NULL) {
				/// UDP Session is not exists
				udp_session_t stmp;
				
				stmp.laddr = caddr;
				stmp.laddr_len = sizeof(stmp.laddr);
				stmp.raddr = addr_parse(otcfg_target_host, otcfg_target_port);
				stmp.raddr_len = sizeof(stmp.raddr);
				
				/// Connect to remote
				stmp.fd = socket(AF_INET, SOCK_DGRAM, 0);
				if (stmp.fd < 0) {
					OT_LOGE("socket() fail while connecting to target host: %s\n", strerror(errno));
					continue;
				}
				ret = connect(stmp.fd, (struct sockaddr*)&stmp.raddr, stmp.raddr_len);
				if (ret < 0) {
					OT_LOGE("connect() fail while connecting to target host: %s\n", strerror(errno));
					continue;
				}
				else {
					OT_LOGI("Connect to %s:%d in UDP\n", inet_ntoa(stmp.raddr.sin_addr), ntohs(stmp.raddr.sin_port));
				}
				
				/// Add to UDP session
				s = udps_add(stmp);
				if (s == NULL) {
					OT_LOGE("Can't add %s:%d to UDP session\n", inet_ntoa(stmp.laddr.sin_addr), ntohs(stmp.laddr.sin_port));
					continue;
				}
				OT_LOGD("Added %s:%d to UDP session\n", inet_ntoa(stmp.laddr.sin_addr), ntohs(stmp.laddr.sin_port));
				
				/// Update fdset
				if (stmp.fd > nfds) {
					nfds = stmp.fd;
				}
				FD_SET(stmp.fd, &initfds);
			}
			
			/// UDP session exists, or has been added
			
			/// Encode or decode data
			if (otcfg_side == OT_SIDE_SERVER) {
				/// Decode
				obfsem_decode(rcvbuf, rcvlen, &buf, &buflen);
			}
			else {
				/// Encode
				obfsem_encode(rcvbuf, rcvlen, &buf, &buflen);
			}
			
			/// Forwar data
			s->atime = curtime;
			ret = sendto(s->fd, buf, buflen, 0, (struct sockaddr*)&s->raddr, s->raddr_len);
			if (ret == 0) {
				OT_LOGI("Connection to target host %s:%d lost\n", inet_ntoa(s->raddr.sin_addr), ntohs(s->raddr.sin_port));
			}
			else if (ret < 0) {
				OT_LOGD("sendto() fail: %s\n", strerror(errno));
			}
			else {
				OT_LOGD("Sent %d bytes to target host %s:%d\n", ret, inet_ntoa(s->raddr.sin_addr), ntohs(s->raddr.sin_port));
			}
		}

		/// 从远程主机收到数据
		for (fd = 0; fd <= 1024; fd++) {	/// FIXME: Should traverse UDP session rather than such bruce
			if (!FD_ISSET(fd, &rfds) || fd == lfd) {
				continue;
			}
			
			raddr_len = sizeof(raddr);
			rcvlen = recvfrom(fd, rcvbuf, sizeof(rcvbuf), 0, (struct sockaddr*)&raddr, &raddr_len);
			if (rcvlen > 0) {
				OT_LOGD("Recived %d bytes from remote %s:%d\n", rcvlen, inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
			}
			else if (rcvlen == 0) {
				OT_LOGD("Remote connection broken\n");
				continue;	/// Continue handle next connection
			}
			else {
				OT_LOGE("recvfrom() fail: %s\n", strerror(errno));
				continue;	/// Continue handle next connection
			}
			
			s = udps_search_byfd(fd);
			if (s == NULL) {
				OT_LOGD("Unknown packet from %s:%d\n", inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));
				continue;
			}

			/// Encode or decode data
			if (otcfg_side == OT_SIDE_SERVER) {
				/// Encode
				obfsem_encode(rcvbuf, rcvlen, &buf, &buflen);
			}
			else {
				/// Decode
				obfsem_decode(rcvbuf, rcvlen, &buf, &buflen);
			}

			/// Forward data
			s->atime = curtime;
			ret = sendto(lfd, buf, buflen, 0, (struct sockaddr*)&s->laddr, s->laddr_len);
			if (ret == 0) {
				OT_LOGI("Connection to target host %s:%d lost\n", inet_ntoa(s->laddr.sin_addr), ntohs(s->laddr.sin_port));
			}
			else if (ret < 0) {
				OT_LOGD("sendto() fail: %s\n", strerror(errno));
			}
			else {
				OT_LOGD("Sent %d bytes to client host %s:%d\n", ret, inet_ntoa(s->laddr.sin_addr), ntohs(s->laddr.sin_port));
			}
		}	/// End of 遍历 UDP 连接列表
	} /// End of while()
}


int ot_listen() {
	int fsd;
	int ret;
	int lisport;
	struct sockaddr_in addr;
	
	if (otcfg_side == OT_SIDE_SERVER) {
		lisport = otcfg_server_port;
	}
	else {
		lisport = otcfg_client_port;
	}
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(lisport);
	addr.sin_addr.s_addr = 0;	/// 0.0.0.0
	
	fsd = socket(AF_INET, otcfg_proto, 0);
	if (fsd <= 0) {
		perror("socket");
		exit(-1);
	}
	
	ret = bind(fsd, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		OT_LOGE("Could not bind on address %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		exit(-2);
	}


	if (otcfg_proto == SOCK_STREAM) {
		ot_listen_tcp(fsd, lisport);
	}
	else if (otcfg_proto == SOCK_DGRAM) {
		ot_tunneling_udp(fsd);
	}
	else {
		OT_LOGE("Unknown protocol `%d'\n", otcfg_proto);
	}
	
	return 0;
}

/**
 * 设置流量混淆方法
 * 
 * @const char*	流量混淆方法名字以及参数，格式为 <method_name>[,parameters]...
 * @return int	成功返回 0,否则返回其他值。
 */
int obfs_usemethod(char* method) {
	char* str;
	char* tmp;
	static char mname[128] = {0};
	
	obfsem_encode = NULL;
	obfsem_decode = NULL;
	obfsem_version = NULL;
	obfsem_init = NULL;
	
	tmp = alloca(strlen(method) + 1);
	strcpy(tmp, method);
	
	str = strtok(tmp, ",");
	if (str == NULL) {
		return -1;
	}
	
	strncpy(mname, str, sizeof(mname) - 1);
	obfsem_name = mname;
	
	/// 先处理内建的方法
	if (strcasecmp(mname, "random") == 0) {
		obfsem_init = obfsem_random_init;
		obfsem_encode = obfsem_randomize_encode;
		obfsem_decode = obfsem_randomize_decode;
		return 0;
	}
	else if (strcasecmp(mname, "xor") == 0) {
		obfsem_init = obfsem_xor_init;
		obfsem_encode = obfsem_xor_encode;
		obfsem_decode = obfsem_xor_decode;
		return 0;
	}
	else if (strcasecmp(mname, "keep") == 0) {
		obfsem_encode = obfsem_keep_encode;
		obfsem_decode = obfsem_keep_decode;
		return 0;
	}
	
	/// 使用插件提供的方法
	
	/// TODO: Load plugin dynamically
	
	return -2;
}

int main(int argc, char* argv[]) {
	int opt;
	int ret;
	int i;
	
	if (argc < 2) {
		fprintf(stderr, "Type `%s -h' for help\n", argv[0]);
		exit(0);
	}
	
	/// Parse arguments
	
	otcfg_proto = SOCK_STREAM;	/// Default to TCP protocol
	
	while ((opt = getopt(argc, argv, "s:t:c:m:u::v::h")) != -1) {
		char* t;
		char tstr2[1024];
		
		switch (opt) {
			case 's':
				/// Server side, listen on 
				otcfg_side = OT_SIDE_SERVER;
				otcfg_server_port = atoi(optarg);

				if (otcfg_server_port == 0) {
					OT_LOGE("You must specify server listen port between 1 and 65535\n");
					exit(-1);
				}

				break;
			
			case 't':
				/// Target host <domain|IP>:<port>
				strncpy(tstr2, optarg, sizeof(tstr2) - 1);
				
				t = strtok(tstr2, ":");
				if (t != NULL) {
					strncpy(otcfg_target_host, t, sizeof(otcfg_target_host) - 1);
				}
				
				t = strtok(NULL, ":");
				if (t != NULL) {
					otcfg_target_port = atoi(t);
				}
				else {
					OT_LOGE("You must specify target host port\n");
					exit(-1);
				}
				
				break;
			
			case 'c':
				/// Client side				
				otcfg_side = OT_SIDE_CLIENT;
				otcfg_client_port = atoi(optarg);
				
				if (otcfg_client_port == 0) {
					OT_LOGE("You must specify port between 1 and 65535 listen on\n");
					exit(-1);
				}

				break;
				
			case 'm':
				ret = obfs_usemethod(optarg);
				if (ret == 0 && obfsem_init != NULL) {
					ret = obfsem_init(optarg);
				}
				
				if (ret != 0) {
					OT_LOGW("No obfs method specified, traffic will not be handle, that is, traffic will be tunneling in plain\n");
					obfsem_encode = obfsem_keep_encode;
					obfsem_decode = obfsem_keep_decode;
				}
				else {
					OT_LOGI("Use obfs method %s\n", obfsem_name);
				}
				
				
				break;
			
			case 'u':
				otcfg_proto = SOCK_DGRAM;
				if (optarg == NULL) {
					otcfg_udp_ttl = 120;
				}
				else {
					otcfg_udp_ttl = atoi(optarg);
				}
				if (otcfg_udp_ttl <= 0) {
					otcfg_udp_ttl = 120;
				}
				
				OT_LOGI("Use UDP protocol\n");
				OT_LOGI("UDP connection live time set to %d seconds\n", otcfg_udp_ttl);
				
				break;
			
			case 'v':
				otcfg_log_level++;
				if (optarg != NULL) {
					for (i = 0; optarg[i] != 0x00; i++) {
						otcfg_log_level++;
					}
				}
				
				break;
			
			case 'h':
			default:
				fprintf(stderr, "Usage: %s <<-s|-c> port> [-t <domain|IP>[:port]] [-u [timeout]]\n", argv[0]);
				exit(0);
				break;
		}
	}
	
	switch (otcfg_side) {
		case OT_SIDE_CLIENT:
			OT_LOGI("Run in CLIENT mode, listen on port %d\n", otcfg_client_port);
			OT_LOGI("Remote server is %s:%d\n", otcfg_target_host, otcfg_target_port);
			break;
			
		case OT_SIDE_SERVER:
			OT_LOGI("Run in SERVER mode, listen on port %d\n", otcfg_server_port);
			OT_LOGI("Target server is %s:%d\n", otcfg_target_host, otcfg_target_port);
			break;
			
		default:
			OT_LOGE("You must specify running mode (as SERVER or CLIENT)\n");
			exit(-1);
			break;
	}
	
	/// 如果没有指定使用什么方法的话就不处理流量
	if (obfsem_encode == NULL) {
		OT_LOGW("No obfs method spicified by -o option, traffic will be tunneling in plain\n");
		obfs_usemethod("keep");
	}
	
	ot_listen();
	
	return 0;
}
