#include <time.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <hawkc.h>
#include <ciron.h>
#include "ticket.h"

/*
 * ciron user-provided buffer sizes. The size has been determined by using
 * some usual tickets, observing the required sizes and then adding a fair amount of
 * space. E.g. Having seen 350 bytes required I choose 1024 for the buffer.
 */
#define ENCRYPTION_BUFFER_SIZE 1024
#define OUTPUT_BUFFER_SIZE 512

/*
 * Hawk uses timestamps to limit the validity of nonces. ALLOWED_SKEW
 * defines * the tolerance for client and server clock deviation.
 */
#define ALLOWED_SKEW 1

/*
 * We differentiate tickets that grant access to only-safe and safe and
 * unsafe HTTP methods.
 * This macro is used to test what kind of method we have.
 */
#define IS_UNSAFE_METHOD(m) (!( \
		((m) == NGX_HTTP_GET) || \
		((m) == NGX_HTTP_HEAD) || \
		((m) == NGX_HTTP_OPTIONS) || \
		((m) == NGX_HTTP_PROPFIND) \
		))

/*
 * Module per-location configuration.
 */
typedef struct {
	/* Authentication realm a given ticket must grant access to */
    ngx_http_complex_value_t  *realm;
    /* iron password to unseal received access tickets. */
    ngx_http_complex_value_t  *iron_password;
} ngx_http_dlg_auth_loc_conf_t;


/*
 * Functions for configuration handling
 */
static ngx_int_t ngx_http_dlg_auth_init(ngx_conf_t *cf);
static void *ngx_http_dlg_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dlg_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
/*
 * Functions for request processing
 */
static ngx_int_t ngx_dlg_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_dlg_auth_authenticate(ngx_http_request_t *r, ngx_str_t iron_password, ngx_str_t realm);
static void ngx_dlg_auth_rename_authorization_header(ngx_http_request_t *r);
static ngx_int_t ngx_dlg_auth_send_simple_401(ngx_http_request_t *r, ngx_str_t *realm);
static void get_host_and_port(ngx_str_t host_header, ngx_str_t *host, ngx_str_t *port);

/*
 * The configuration directives
 */
static ngx_command_t ngx_dlg_auth_commands[] = {

	{ ngx_string("dlg_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
	                       |NGX_CONF_TAKE1,
	  ngx_http_set_complex_value_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_dlg_auth_loc_conf_t, realm),
	  NULL },

	{ ngx_string("dlg_auth_iron_pwd"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
	                       |NGX_CONF_TAKE1,
	  ngx_http_set_complex_value_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_dlg_auth_loc_conf_t, iron_password),
	  NULL },

    ngx_null_command /* command termination */
};

/*
 * The static (configuration) module context.
 */
static ngx_http_module_t  nginx_dlg_auth_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_dlg_auth_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dlg_auth_create_loc_conf,   /* create location configuration */
    ngx_http_dlg_auth_merge_loc_conf     /* merge location configuration */
};

/*
 * The module definition itself.
 */
ngx_module_t  nginx_dlg_auth_module = {
    NGX_MODULE_V1,
    &nginx_dlg_auth_module_ctx,       /* module context */
    ngx_dlg_auth_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * Initialization function to register handler to
 * access phase.
 */
static ngx_int_t ngx_http_dlg_auth_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if( (h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers)) == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_dlg_auth_handler;
    return NGX_OK;
}

/*
 * Allocate new per-location config
 */
static void *ngx_http_dlg_auth_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_dlg_auth_loc_conf_t  *conf;
    if( (conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dlg_auth_loc_conf_t))) == NULL) {
        return NULL;
    }
    return conf;
}

/*
 * Inherit per-location configuration if it has not been set
 * specifically.
 */
static char * ngx_http_dlg_auth_merge_loc_conf(ngx_conf_t *cf, void *vparent, void *vchild) {
    ngx_http_dlg_auth_loc_conf_t  *parent = (ngx_http_dlg_auth_loc_conf_t*)vparent;
    ngx_http_dlg_auth_loc_conf_t  *child = (ngx_http_dlg_auth_loc_conf_t*)vchild;

    if (child->realm == NULL) {
        child->realm = parent->realm;
    }
    if (child->iron_password == NULL) {
        child->iron_password = parent->iron_password;
    }
    return NGX_CONF_OK;
}

/*
 * The actual handler - this is called during access phase.
 *
 * What we do here is to parse the authorization header,
 * validate the Hawk signature and then check access
 * grant using the sealed ticket provided as the Hawk ID.
 *
 * If authentication and authorization succeeds, we strip the
 * authorization header from the request to enable caching
 *
 * NGINX does not support request header removal, so instead
 * we just rename the header.
 * (Removal is next to impossible because headers are stored
 * in arrays and removing a header would invalidate pointers
 * to it, held by various other portions of the processed
 * request)
 */
static ngx_int_t ngx_dlg_auth_handler(ngx_http_request_t *r) {
    ngx_http_dlg_auth_loc_conf_t  *alcf;
    ngx_str_t realm;
    ngx_str_t iron_password;
    ngx_int_t rc;

    /*
     * First, get the configuration and do some checking, whether
     * we actually should do anything.
     */

    alcf = ngx_http_get_module_loc_conf(r, nginx_dlg_auth_module);
    if (alcf->realm == NULL) {
        return NGX_DECLINED;
    }
    if (alcf->iron_password == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }
    /*
     * User can disable ourselves by setting the realm to 'off'
     */
    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->iron_password, &iron_password) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Authorization header presence is required, of course.
     */

    if (r->headers_in.authorization == NULL) {
    	/* FIXME: Maybe details about necessary access should be sent, too */
    	return ngx_dlg_auth_send_simple_401(r,&realm);
    }

    /*
     * Authenticate and authorize and 'remove' (rename) authorization header if ok.
     */
    if( (rc =  ngx_dlg_auth_authenticate(r,iron_password,realm)) != NGX_OK) {
    	return rc;
    }
    ngx_dlg_auth_rename_authorization_header(r);

    return NGX_OK;
}

/*
 * This is the heart of the module, where authentication and authorization
 * takes place.
 *
 */
static ngx_int_t ngx_dlg_auth_authenticate(ngx_http_request_t *r, ngx_str_t iron_password, ngx_str_t realm) {

	/*
	 * Variables necessary for Hawk.
	 */
	HawkcError he;
	struct HawkcContext hawkc_ctx;
	int hmac_is_valid;
	ngx_str_t host;
	ngx_str_t port;
	ngx_str_t h; /* FIXME - remove; see below */

	/*
	 * Variables necessary for ciron.
	 */
    struct CironContext ciron_ctx;
	CironError ce;
	/* FIXME: rename in ciron - and the algos, too */
	CironOptions encryption_options = CIRON_DEFAULT_ENCRYPTION_OPTIONS;
    CironOptions integrity_options = CIRON_DEFAULT_INTEGRITY_OPTIONS;
	unsigned char encryption_buffer[ENCRYPTION_BUFFER_SIZE];
	unsigned char output_buffer[OUTPUT_BUFFER_SIZE];
	int check_len;
	int output_len;

	/*
	 * Ticket processing and authorization checking.
	 */
	TicketError te;
	struct Ticket ticket;
	time_t now;

	/*
	 * Workaround localhost problem during development.
	 * FIXME: remove and adjust below.
	 */
	h.data = (u_char*)"***REMOVED***";
	h.len = 11;

	/*
	 * Get original request host and port from host header
	 * FIXME Please see https://github.com/algermissen/nginx-dlg-auth/issues/5
	 */
	get_host_and_port(r->headers_in.host->value,&host,&port);
	if(port.len == 0) {
		port.data = (u_char*)"80"; /* Default HTTP port */
		port.len = 2;
	}

	/*
	 * Initialize Hawkc context with original request data
	 */

	hawkc_context_init(&hawkc_ctx);
	hawkc_context_set_method(&hawkc_ctx,(char*)r->method_name.data, r->method_name.len);
	hawkc_context_set_path(&hawkc_ctx,(char*)r->unparsed_uri.data, r->unparsed_uri.len);
	hawkc_context_set_host(&hawkc_ctx,(char*)host.data,host.len);
	hawkc_context_set_port(&hawkc_ctx,(char*)port.data,port.len);

	/*
	 * Parse Hawk Authorization header.
	 */
	if( (he = hawkc_parse_authorization_header(&hawkc_ctx,(char*)r->headers_in.authorization->value.data, r->headers_in.authorization->value.len)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to parse Authorization header: %s" , hawkc_get_error(&hawkc_ctx));
		if(he == HAWKC_BAD_SCHEME_ERROR) {
			return ngx_dlg_auth_send_simple_401(r,&realm);
		}
		if(he == HAWKC_PARSE_ERROR) {
			return NGX_HTTP_BAD_REQUEST;
		}
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * ciron requires the caller to provide buffers for the decryption process
	 * and the unsealed result. We are providing static buffers, but still need
	 * to check the size. If the static buffers are not enough, we have
	 * received an invalid ticket anyway.
	 */

	if( (check_len = (int)ciron_calculate_encryption_buffer_length(encryption_options, hawkc_ctx.header_in.id.len)) > sizeof(encryption_buffer)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Required encryption buffer length %d too big. This might indicate an attack",
				check_len);
		return NGX_HTTP_BAD_REQUEST;
	}

	if( (check_len = (int)ciron_calculate_unseal_buffer_length(encryption_options, integrity_options,hawkc_ctx.header_in.id.len)) > sizeof(output_buffer)) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Required output buffer length %d too big. This might indicate an attack",
					check_len);
			return NGX_HTTP_BAD_REQUEST;
	}

	/*
	 * The sealed ticket is the Hawk id parameter. We unseal it, parse the ticket JSON
	 * and extract password and algorithm to validate the Hawk signature.
	 */
	if( (ce =ciron_unseal(&ciron_ctx,(unsigned char*)hawkc_ctx.header_in.id.data, hawkc_ctx.header_in.id.len, iron_password.data, iron_password.len,
			encryption_options, integrity_options, encryption_buffer, output_buffer, &output_len)) != CIRON_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to unseal ticket: %s" , ciron_get_error(&ciron_ctx));
			return NGX_HTTP_BAD_REQUEST;
	}
	if( (te = ticket_from_string(&ticket , (char*)output_buffer,output_len)) != OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to parse ticket JSON, %s" , ticket_strerror(te));
		return NGX_HTTP_BAD_REQUEST;
	}

	/*
	 * Validate the HMAC signature of the request.
	 */

	if( (he = hawkc_validate_hmac(&hawkc_ctx, ticket.hawkAlgorithm, (unsigned char*)ticket.pwd.data, ticket.pwd.len,&hmac_is_valid)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to validate request signature: %s" , hawkc_get_error(&hawkc_ctx));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if(!hmac_is_valid) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid signature in %V" ,&(r->headers_in.authorization->value) );
		return ngx_dlg_auth_send_simple_401(r,&realm);
	}

	/*
	 * Check request timestamp, allowing for some skew.
	 */

	time(&now);
	if(hawkc_ctx.header_in.ts < now - ALLOWED_SKEW || hawkc_ctx.header_in.ts > now + ALLOWED_SKEW) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Clock skew too large");
		/* FIXME: send suggested TS
		 * See https://github.com/algermissen/nginx-dlg-auth/issues/4
		 */
		return ngx_dlg_auth_send_simple_401(r,&realm);
	}

	/* FIXME Check nonce, see https://github.com/algermissen/nginx-dlg-auth/issues/1 */

	/*
	 * Now the request has been authenticated by way of Hawk and we use the ticket
	 * itself to check access rights.
	 */

	/*
	 * Tickets contain a parameter rw which has to be set to true to grant
	 * access using unsafe HTTP methods.
	 */
	if(IS_UNSAFE_METHOD(r->method)) {
		if(ticket.rw == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Ticket does not represent grant for unsafe methods");
			return NGX_HTTP_FORBIDDEN;
		}
	}

	/*
	 * Now we check whether the ticket applies to the necessary scope.
	 */
	/*
	if(!ticket_has_scope(&ticket,host,_realm)) {
	*/
	if(!ticket_has_scope(&ticket,h.data, h.len,realm.data,realm.len)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ticket does not have scope %V" ,&(realm) );
		return ngx_dlg_auth_send_simple_401(r,&realm);
	}

	/*
	 * Check whether ticket has expired.
	 */
	if(ticket.exp < now) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Ticket has expired");
		/* FIXME: probably set defined error code in auth header. This is a todo for the overall auth delegation (e.g. Oz) */
		return ngx_dlg_auth_send_simple_401(r,&realm);

	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Hawk access using token; client=%V, expires=%d rw=%s" ,
			&(ticket.client) , ticket.exp , ticket.rw ? "true" : "false");

	return NGX_OK;
}

/*
 * Removing request headers is next to impossible in NGINX because
 * they come as an array. Removing would invalidate various pointers
 * held by other parts of the request struct. This is way too error
 * prone, so renaming the headers seems like the better solution to
 * make the upstream response cacheable.
 * We rename be changing the first two characters to 'x-', thus
 * Authorization will be passed as X-thorization.
 */
static void ngx_dlg_auth_rename_authorization_header(ngx_http_request_t *r) {
	ngx_uint_t nelts;
	size_t size;
	unsigned int i;

	/*
	 * Headers come as a list which we have to iterate over to find
	 * the appropriate bucket.
	 * FIXME: I think we can achieve the same by simply using the authorization pointer
	 * and then setting it to NULL.
	 */

	nelts = r->headers_in.headers.part.nelts;
	size = r->headers_in.headers.size;

  	for(i=0; i < nelts; i++) {
   		void *elt;
   		ngx_table_elt_t *data;
   		elt = ((char*)r->headers_in.headers.part.elts) + (i * size); /* FIXME warning void* in arithm. */
   		data = (ngx_table_elt_t*)elt;

   		if(data->key.len == 13 && memcmp(data->lowcase_key,"authorization",13) == 0) {
   			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, " Removing Authorization request header");
   			memcpy(data->key.data,"X-",2);
   			memcpy(data->lowcase_key,"x-",2);
   			r->headers_in.authorization = NULL;
   			break;
   		}
   	}
}

/*
 * This implements a very basic WWW-Authenticate header. It needs to
 * be enhanced, once Hawkc provides better support for it,
 * See https://github.com/algermissen/nginx-dlg-auth/issues/4
 */
static ngx_int_t ngx_dlg_auth_send_simple_401(ngx_http_request_t *r, ngx_str_t *realm) {
    	ngx_str_t challenge;
    	unsigned char *p;
    	/*
    	 * Add new header.
    	 */
    	if( (r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers)) == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.www_authenticate->hash = 1;
        ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");

        challenge.len = 13 + realm->len;
        if( (challenge.data = ngx_pnalloc(r->pool, challenge.len)) == NULL) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        p = ngx_cpymem(challenge.data, (unsigned char*)"Hawk realm=\"",12);
        p = ngx_cpymem(p, realm->data, realm->len);
        p = ngx_cpymem(p, (unsigned char*)"\"", 1);

        r->headers_out.www_authenticate->value = challenge;

        return NGX_HTTP_UNAUTHORIZED;
}




/*
 * Obtain original host and port from HTTP Host header value.
 *
 * Callers need to check the port len themselves and if it is 0
 * they are responsible for setting the default port.
 */
static void get_host_and_port(ngx_str_t host_header, ngx_str_t *host, ngx_str_t *port) {
		u_char *p;
		unsigned int i;
		port->len = 0;
		p = host_header.data;
		/* Extract host */
		host->data = p;
		i=0;
		while(i < host_header.len && *p != ':') {
			p++;
			i++;
		}
		host->len = i;
		/* If we found delimiter and still have stuff to read, process port. */
		if(*p == ':' && i+1<host_header.len) {
			p++;
			i++;
			port->data = p;
			while(i < host_header.len) {
				p++;
				i++;
				port->len++;
			}
		}
	}

