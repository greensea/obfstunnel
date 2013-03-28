#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "obfstunnel.h"
#include "udpsession.h"

udp_session_t* udps_head = NULL;


udp_session_t* udps_search_byfd(int fd) {
	udp_session_t* p;
	
	for (p = udps_head; p != NULL; p = p->next) {
		if (p->fd == fd) {
			return p;
		}
	}
	
	return NULL;
}

udp_session_t* udps_search_byladdr(struct sockaddr_in addr) {
	udp_session_t* p;
	
	for (p = udps_head; p != NULL; p = p->next) {
		if (memcmp(&p->laddr, &addr, sizeof(p->laddr)) == 0) {
			return p;
		}
	}
	
	return NULL;
}

/**
 * Add a new sesion
 * 
 * @return udp_session_t*	Pointer to the node new added
 */
udp_session_t* udps_add(udp_session_t sess) {
	udp_session_t* n;
	
	n = (udp_session_t*)malloc(sizeof(udp_session_t));
	if (n == NULL) {
		perror("malloc");
		return NULL;
	}
	
	memcpy(n, &sess, sizeof(*n));
	
	n->next = udps_head;
	udps_head = n;
	
	return n;
}

/**
 * Delete an UDP session node
 * 
 * @return int	0 for success, negative for fail
 */
int udps_delete(udp_session_t* sess) {
	udp_session_t* p;
	
	if (sess == udps_head) {
		free(sess);
		udps_head = NULL;
	}
	else {
		/// Search the prev node of *sess
		for (p = udps_head; p->next != sess; p = p->next) {
			if (p == NULL) {
				OT_LOGD("No udp session %08X found\n", (unsigned int)sess);
				return -1;
			}
		}
		
		p->next = sess->next;
		free(sess);
	}
	
	return 0;
}

/// Search timed out UDP sessions and delete them
int udps_cleanup(int ttl) {
	udp_session_t* p;
	udp_session_t* prev;
	time_t curtime;
	int n = 0;
	
	curtime = time(NULL);
	
	p = udps_head;
	prev = NULL;
	while (p != NULL) {
		if (curtime - p->atime > ttl) {
			n++;
			
			OT_LOGD("curtime - p->atime = %d - %d = %d, s->fd=%d, ttl=%d\n", (int)curtime, (int)p->atime, (int)(curtime - p->atime), p->fd, ttl);
			
			// <!> Shutdown fds
			shutdown(p->fd, SHUT_RDWR);
			close(p->fd);
			
			if (prev == NULL) {
				udps_head = p->next;
				free(p);
				p = udps_head;
			}
			else {
				prev->next = p->next;
				free(p);
				p = prev->next;
			}
			
		}
		else {
			prev = p;
			p = p->next;
		}
	}
	
	OT_LOGD("Deleted %d timeout nodes\n", n);
	
	return 0;
}

/**
 * Rebuild fdset corresponding to current UDP sessions
 * 
 * @return int	Max number of fd
 */
int udps_fdset(fd_set* fds) {
	int n = -1;
	udp_session_t* p;
	
	if (fds == NULL) {
		return -1;
	}
	
	FD_ZERO(fds);
	
	for (p = udps_head; p != NULL; p = p->next) {
		if (p->fd > n) {
			n = p->fd;
		}
		
		FD_SET(p->fd, fds);
	}
	
	return n;
}
