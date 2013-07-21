#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>
#include "ticket.h"
#include "jsmn.h"


/*
 * This max number of tokens must be large enough to handle usual tickets.
 * The number of tokens varies with the number of scopes. MAX_TOKENS has
 * been calculated like this:
 * 1 Token for the overall object
 * 16 Tokens for the 8 fields (2 tokens each)
 * MAX_SCOPE (see ticket.h) tokens for the scopes
 * => 27 tokens.
 *
 */
#define MAX_TOKENS 27


typedef struct Builder {
	jsmn_parser parser;
	jsmntok_t tokens[MAX_TOKENS];
	int i;
	Ticket ticket;
	int ntokens;
	char *input;
} *Builder;

static void ticket_init(Ticket t);
static TicketError do_algo(Builder builder);
static TicketError do_string(Builder builder, HawkcString *s);
static TicketError do_rw(Builder builder, int *v);
static TicketError do_time(Builder builder, time_t *tp);
static TicketError do_scopes(Builder builder);


/** Error strings used by ticket_strerror
 *
 */
static char *error_strings[] = {
		"Success", /* OK */
		"Ticket JSON corrupted", /* ERROR_JSON_INVAL */
		"Too many JSON tokens in ticket", /* ERROR_JSON_NTOKENS */
		"Ticket JSON misses a part", /* ERROR_JSON_PART */
		"Not enough tokens in ticket JSON to parse expected token", /* ERROR_MISSING_EXPECTED_TOKEN */
		"Unexpected token type", /* ERROR_UNEXPECTED_TOKEN_TYPE */
		"Unexpected token name", /* ERROR_UNEXPECTED_TOKEN_NAME */
		"Unable to parse time value", /* ERROR_PARSE_TIME_VALUE */
		"Too many scopes in ticket", /* ERROR_NSCOPES */
		"Unknown Hawk algorithm", /* ERROR_UNKNOWN_HAWK_ALGORITHM */
		"Error" , /* ERROR */
		NULL
};

char* ticket_strerror(TicketError e) {
	assert(e >= OK && e <= ERROR);
	return error_strings[e];
}
TicketError ticket_from_string(Ticket ticket,char *json_string,unsigned int len) {
	TicketError e;
	jsmnerr_t jsmn_error;
	struct Builder builder;

	memset(&builder,0,sizeof(builder));

	jsmn_init(&(builder.parser));
	builder.ticket = ticket;
	builder.input = json_string;

	ticket_init(builder.ticket);

	if( (jsmn_error = jsmn_parse(&(builder.parser), builder.input, len, builder.tokens, MAX_TOKENS)) != JSMN_SUCCESS) {
		switch(jsmn_error) {
		case JSMN_ERROR_INVAL:
			return ERROR_JSON_INVAL;
		case JSMN_ERROR_NOMEM:
			return ERROR_JSON_NTOKENS;
		case JSMN_ERROR_PART:
			return ERROR_JSON_PART;
		default:
			/* Should never be reached */
			return OK;
		}
		/* Should never be reached */
		return ERROR;
	}

	builder.ntokens = builder.parser.toknext;

	for (builder.i = 0; builder.i< builder.parser.toknext;builder.i++) {
        jsmntok_t *t = &(builder.tokens[builder.i]);
        unsigned int length = t->end - t->start;
        char *s = builder.input + t->start;

        if (t->type == JSMN_STRING) {
        	if(length == 6 && strncmp(s,"client",length) == 0) {
        		if( (e = do_string(&builder,&(ticket->client))) != OK) {
        			return e;
        		}
        	} else if(length == 3 && strncmp(s,"pwd",length) == 0) {
        		if( (e = do_string(&builder,&(ticket->pwd))) != OK) {
        			return e;
        		}
        	} else if(length == 13 && strncmp(s,"hawkAlgorithm",length) == 0) {
        		if( (e = do_algo(&builder)) != OK) {
        			return e;
        		}
        	} else if(length == 5 && strncmp(s,"owner",length) == 0) {
        		if( (e = do_string(&builder,&(ticket->owner))) != OK) {
        			return e;
        		}
        	} else if(length == 6 && strncmp(s,"scopes",length) == 0) {
        		if( (e = do_scopes(&builder)) != OK) {
        			return e;
        		}
        	} else if(length == 4 && strncmp(s,"user",length) == 0) {
        		if( (e = do_string(&builder,&(ticket->user))) != OK) {
        			return e;
        		}
        	} else if(length == 3 && strncmp(s,"exp",length) == 0) {
        		if( (e = do_time(&builder,&(ticket->exp))) != OK) {
        			return e;
        		}
           	} else if(length == 2 && strncmp(s,"rw",length) == 0) {
           		if( (e = do_rw(&builder,&(ticket->rw))) != OK) {
           			return e;
           		}
        	} else {
        		return ERROR_UNEXPECTED_TOKEN_NAME;
        	}
        } else if (t->type == JSMN_PRIMITIVE) {
        	/* Primitives are handled in dedicated functions */
        	return ERROR_UNEXPECTED_TOKEN_TYPE;
        } else if (t->type == JSMN_ARRAY) {
        	/* Scopes array is handled by dedicated function. Should never come here */
        	return ERROR_UNEXPECTED_TOKEN_TYPE;
        } else if (t->type == JSMN_OBJECT) {
        	/* Only object we should encounter is the ticket itself, which is at i=0 */
        	if(builder.i != 0) {
        		return ERROR_UNEXPECTED_TOKEN_TYPE;
        	}
        } else {
       		return ERROR_UNEXPECTED_TOKEN_TYPE;
        }
    }
	return OK;
}

TicketError do_string(Builder builder, HawkcString *s) {
	jsmntok_t *t;
	builder->i++;
	if(builder->i >= builder->ntokens) {
		return ERROR_MISSING_EXPECTED_TOKEN;
	}
	t = &(builder->tokens[builder->i]);
	if(t->type != JSMN_STRING) {
		return ERROR_UNEXPECTED_TOKEN_TYPE;
	}
   s->data = builder->input+t->start;
   s->len = t->end - t->start;
   return OK;
}

TicketError do_time(Builder builder, time_t *tp) {
	time_t x = 0;
	char *p;
	int i;
	jsmntok_t *t;
	builder->i++;
	if(builder->i >= builder->ntokens) {
		return ERROR_MISSING_EXPECTED_TOKEN;
	}
	t = &(builder->tokens[builder->i]);
	if(t->type != JSMN_PRIMITIVE) {
		return ERROR_UNEXPECTED_TOKEN_TYPE;
	}
	p = builder->input+t->start;
	i = t->start;
	while(i < t->end) {
		if(!isdigit(*p)) {
			return ERROR_PARSE_TIME_VALUE;
		}
		x = (x * 10) + digittoint(*p);
		p++;
		i++;
	}
	*tp = x;
	return OK;
}

TicketError do_rw(Builder builder, int *v) {
	jsmntok_t *t;
	*v = 0; /* Use rw=false as a safe default */
	builder->i++;
	if(builder->i >= builder->ntokens) {
		return ERROR_MISSING_EXPECTED_TOKEN;
	}
	t = &(builder->tokens[builder->i]);
	/* check for 'true' only, false is safe default for rw */
	if( (t->type == JSMN_PRIMITIVE) && (t->end - t->start == 4) && (strncmp(builder->input+t->start,"true",4) == 0)) {
		*v = 1;
	}
	return OK;
}

TicketError do_scopes(Builder builder) {
	jsmntok_t *t;
	int i;
	builder->i++;
	if(builder->i >= builder->ntokens) {
		return ERROR_MISSING_EXPECTED_TOKEN;
	}
	t = &(builder->tokens[builder->i]);
	if(t->type != JSMN_ARRAY) {
		return ERROR_UNEXPECTED_TOKEN_TYPE;
	}
	if(t->size > MAX_SCOPES) {
		return ERROR_NSCOPES;
	}
	for(i=0;i<t->size;i++) {
		do_string(builder,&(builder->ticket->scopes[i]));
	}
	builder->ticket->nscopes = t->size;
	return OK;
}

TicketError do_algo(Builder builder) {
	HawkcString algo;
	HawkcAlgorithm a;
	TicketError e;
	if( (e = do_string(builder,&algo)) != OK) {
		return e;
	}
	if( (a = hawkc_algorithm_by_name(algo.data, algo.len)) == NULL) {
		return ERROR_UNKNOWN_HAWK_ALGORITHM;
	}
	builder->ticket->hawkAlgorithm = a;
	return OK;
}

int ticket_has_scope(Ticket ticket, unsigned char *host, unsigned int host_len, unsigned char *realm, unsigned int realm_len) {
	int i;
	int scope_len = host_len + 1 + realm_len; /* scope='host|realm' */
	for(i=0;i<ticket->nscopes;i++) {
		if(ticket->scopes[i].len == scope_len) {
			char *s = ticket->scopes[i].data;
			if( (memcmp(s,host,host_len) == 0)
					&& (s[host_len] == '|')
					&& (memcmp(s+host_len+1,realm,realm_len) == 0)) {
				return 1;
			}
		}
	}
	return 0;
}

void ticket_init(Ticket t) {
	memset(t,0,sizeof(struct Ticket));
	t->rw = 0; /* false is default */
}

