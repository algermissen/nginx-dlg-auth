#ifndef NGX_DLG_AUTH_TICKET_H
#define NGX_DLG_AUTH_TICKET_H

#include <hawkc.h>
#include <time.h>


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
	unsigned int nscopes;
	time_t exp;
	HawkcAlgorithm hawkAlgorithm;
} *Ticket;

/*
 *
 */
typedef enum {
	OK,
	ERROR_JSON_INVAL,
	ERROR_JSON_NTOKENS,
	ERROR_JSON_PART,
	ERROR_MISSING_EXPECTED_TOKEN,
	ERROR_UNEXPECTED_TOKEN_TYPE,
	ERROR_UNEXPECTED_TOKEN_NAME,
	ERROR_PARSE_TIME_VALUE,
	ERROR_NSCOPES,
	ERROR_UNKNOWN_HAWK_ALGORITHM,
	ERROR
} TicketError;

char* ticket_strerror(TicketError e);

/*
 * Parse a ticket from a json string. Allocation of the ticket is the
 * responsibility of the caller. Usually, you should declare a local struct Ticket and
 * pass a pointer to that.
 */
TicketError ticket_from_string(Ticket ticket,char *b,unsigned int len);

/*
 * Returns 1 if the ticket contains a scope that matches the scope implied
 * by the provided host and realm.
 * A scope name has the form host '|' realm
 */
int ticket_has_scope(Ticket ticket, unsigned char *host, unsigned int host_len, unsigned char *realm, unsigned int realm_len);

#ifdef __cplusplus
} // extern "C"
#endif


#endif
