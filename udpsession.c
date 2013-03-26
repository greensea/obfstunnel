#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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
				OT_DEBUG("No udp session %08X found\n");
				return -1;
			}
		}
		
		p->next = sess->next;
		free(sess);
	}
	
	return 0;
}


