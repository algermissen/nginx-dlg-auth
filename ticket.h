/* The base64.c for the original license of the base64 code */

#ifndef NGX_DLG_AUTH_TICKET_H
#define NGX_DLG_AUTH_TICKET_H

#include <hawkc.h>
#include <time.h>
#include <ngx_http.h>


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SCOPES 10

typedef struct Ticket {
	HawkcString client;
	HawkcString user;
	HawkcString owner;
	HawkcString pwd;
	int rw;
	HawkcString scopes[MAX_SCOPES];
	int nscopes;
	time_t exp;
	HawkcAlgorithm hawkAlgorithm;
} *Ticket;

typedef enum { OK, ERROR } Error;

Error ticket_from_string(Ticket ticket,char *b,unsigned int len,ngx_http_request_t *r);




#ifdef __cplusplus
} // extern "C"
#endif


#endif
