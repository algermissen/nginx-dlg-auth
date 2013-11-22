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
	size_t nscopes;
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

/*
 * Obtain a string representation of the supplied error code.
 */
char* ticket_strerror(TicketError e);

/*
 * Parse a ticket from a json string. Allocation of the ticket is the
 * responsibility of the caller. Usually, you should declare a local struct Ticket and
 * pass a pointer to that.
 *
 * The ticket parser supports the following JSON structure
 *
 * {
 *   "client":"100001",
 *   "user" : "77762",
 *   "owner" : 55514,
 *   "pwd":"w7*0T6C.0b4C#",
 *   "scopes" ["***REMOVED***|***REMOVED***"],
 *   "rw":false,
 *   "exp":1405688331,
 *   "hawkAlgorithm":"sha256"
 * }
 *
 */
TicketError ticket_from_string(Ticket ticket, char *b, size_t len);


/*
 * Returns 1 if the ticket contains a scope that matches the realm.
 * This function considers scope and realm to match if they are byte-equal.
 */
int ticket_has_scope(Ticket ticket, unsigned char *realm, size_t realm_len) ;

#ifdef __cplusplus
} // extern "C"
#endif


#endif
