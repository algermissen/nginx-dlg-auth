#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "ticket.h"
#include "jsmn.h"

#include <ngx_log.h>




typedef struct Builder {
	jsmn_parser parser;
	jsmntok_t tokens[128]; // a number >= total number of tokens
	int i;
	Ticket ticket;
	char error_string[256];
	int ntokens;
	char *input;

} *Builder;

static Error set_error(Builder builder, const char *fmt, ...);
static Error do_algo(Builder builder);
static Error do_string(Builder builder, HawkcString *s);

void ticket_init(Ticket t) {
	memset(t,0,sizeof(struct Ticket));
}

/*
*/



Error ticket_from_string(Ticket ticket,char *b,unsigned int len,ngx_http_request_t *r) {
	Error e;
	int resultCode;
	struct Builder builder;

	memset(&builder,0,sizeof(builder));

	jsmn_init(&(builder.parser));
	builder.ticket = ticket;
	builder.input = b;

	ticket_init(builder.ticket);

	resultCode = jsmn_parse(&(builder.parser), b, len, builder.tokens, 256);

	builder.ntokens = builder.parser.toknext;

	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-1");

	for (builder.i = 0; builder.i< builder.parser.toknext;(builder.i) =  (builder.i) + 1 ) {
        jsmntok_t *t = &(builder.tokens[builder.i]);
        unsigned int length = t->end - t->start;
        char *s = b+(t->start);
        char x[1024];
        memset(x,0,1024);
        memcpy(x,s,length);

        // Should never reach uninitialized tokens
        // FIXME: remove dep on ngx
        /*
        log_assert(t->start != -1 && t->end != -1);
        */
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-2 %s , %d (i=%d)" , x , length, builder.i);

        if (t->type == JSMN_ARRAY) {
        	builder.i += t->size;
        } else if (t->type == JSMN_OBJECT) {
        	;
        } else if (t->type == JSMN_STRING) {
        	if(length == 6 && strncmp(s,"client",length) == 0) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-3");
        		if( (e = do_string(&builder,&(ticket->client))) != OK) {
        			return e;
        		}
        	} else if(length == 3 && strncmp(s,"pwd",length) == 0) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-4");
        		if( (e = do_string(&builder,&(ticket->pwd))) != OK) {
        			return e;
        		}
        	} else if(length == 13 && strncmp(s,"hawkAlgorithm",length) == 0) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-5");
        		if( (e = do_algo(&builder)) != OK) {
        			return e;
        		}

        	} else {
        		; /* ignore */
        	}
        } else if (t->type == JSMN_PRIMITIVE) {
        		; /* ignore */

        } else {
        	; /* ignore */
        }
    }
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xxx-6");
	/*
	jsmntok_t key = tokens[1];
	unsigned int length = key.end - key.start;
	char keyString[length + 1];
	memcpy(keyString, &yourJson[key.start], length);
	keyString[length] = '\0';
	printf("Key: %s\n", keyString);
	*/

	return OK;
}

Error do_string(Builder builder, HawkcString *s) {
	jsmntok_t *t;
	builder->i++;
	if(builder->i >= builder->ntokens) {
		set_error(builder,"Not enough tokens to parse expected string token");
		return ERROR;
	}
	t = &(builder->tokens[builder->i]);
	if(t->type != JSMN_STRING) {
		set_error(builder,"Token not a string token");
		return ERROR;
	}
   s->data = builder->input+t->start;
   s->len = t->end - t->start;

	return OK;
}


// FIXME: implement a hawkc_algo_by_name(name);
Error do_algo(Builder builder) {
	HawkcString algo;
	HawkcAlgorithm a;
	Error e;
	if( (e = do_string(builder,&algo)) != OK) {
		return e;
	}
	if( (a = hawkc_algorithm_by_name(algo.data, algo.len)) == NULL) {
		return set_error(builder, "Algorithm %s not recognized for by HAWKC", "FIXME");
	}
	builder->ticket->hawkAlgorithm = a;
	return OK;
}




Error set_error(Builder builder, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vsnprintf(builder->error_string, sizeof(builder->error_string), fmt, args);
	va_end(args);
	return ERROR;
}

