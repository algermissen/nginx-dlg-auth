#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <hawkc.h>
#include <ciron.h>
#include "ticket.h"
/*
 * ./configure --add-module=/Users/jan/Projects/NORD/ono/workspace/nginx-dlg-auth
 */

typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t  *password;
} ngx_http_dlg_auth_loc_conf_t;

static ngx_int_t ngx_http_dlg_auth_init(ngx_conf_t *cf);
static void *ngx_http_dlg_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dlg_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_dlg_auth_handler(ngx_http_request_t *r);
static ngx_int_t ngx_dlg_auth_remove_authorization_header(ngx_http_request_t *r);
static ngx_int_t ngx_dlg_auth_send_simple_401(ngx_http_request_t *r);
static void get_host_and_port(ngx_str_t host_header, ngx_str_t *host, ngx_str_t *port);


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
	  offsetof(ngx_http_dlg_auth_loc_conf_t, password),
	  NULL },

    ngx_null_command /* command termination */
};



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

static ngx_int_t
ngx_http_dlg_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_dlg_auth_handler;

    return NGX_OK;
}

static void *
ngx_http_dlg_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dlg_auth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dlg_auth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_dlg_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dlg_auth_loc_conf_t  *prev = parent;
    ngx_http_dlg_auth_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }
    if (conf->password == NULL) {
        conf->password = prev->password;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_dlg_auth_authenticate(ngx_http_request_t *r, ngx_str_t iron_password) {

	HawkcError he;
	struct HawkcContext hawkc_ctx;
	int hmac_is_valid;
	ngx_str_t host;
	ngx_str_t port;

    struct CironContext ciron_ctx;
	CironError ce;
	/* FIXME: rename in ciron - and the algos, too */
	Options encryption_options = DEFAULT_ENCRYPTION_OPTIONS;
    Options integrity_options = DEFAULT_INTEGRITY_OPTIONS;
	unsigned char encryption_buffer[4096]; /* FIXME */
	unsigned char output_buffer[4096]; /* FIXME */
	int output_len;

	struct Ticket ticket;

	/*
	 * Get original request host and port from host header
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
	hawkc_context_set_method(&hawkc_ctx,r->method_name.data, r->method_name.len);
	hawkc_context_set_path(&hawkc_ctx,r->unparsed_uri.data, r->unparsed_uri.len);
	hawkc_context_set_host(&hawkc_ctx,host.data,host.len);
	hawkc_context_set_port(&hawkc_ctx,port.data,port.len);

	/*
	 * Parse Hawk Authorization header.
	 */
	if( (he = hawkc_parse_authorization_header(&hawkc_ctx,r->headers_in.authorization->value.data, r->headers_in.authorization->value.len)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to parse Authorization header: %s" , hawkc_get_error(&hawkc_ctx));
		if(he == HAWKC_BAD_SCHEME_ERROR) {
			return ngx_dlg_auth_send_simple_401(r);
		}
		if(he == HAWKC_PARSE_ERROR) {
			return NGX_HTTP_BAD_REQUEST;
		}
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* FIXME: calculate and check encbuffer and output buffer sizes */

	/*
	 * The sealed ticket is the Hawk id parameter. We unseal it, parse the ticket JSON
	 * and extract password and algorithm to validate the Hawk signature.
	 */
	if( (ce =ciron_unseal(&ciron_ctx,(unsigned char*)hawkc_ctx.header_in.id.data, hawkc_ctx.header_in.id.len, iron_password.data, iron_password.len,
			encryption_options, integrity_options, encryption_buffer, output_buffer, &output_len)) != CIRON_OK) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to unseal ticket: %s" , ciron_get_error(&ciron_ctx));
			return NGX_HTTP_BAD_REQUEST;
	}

	if(ticket_from_string(&ticket , output_buffer,output_len,r) != OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to parse ticket JSON");
		return NGX_HTTP_BAD_REQUEST;
	}


	if( (he = hawkc_validate_hmac(&hawkc_ctx, ticket.hawkAlgorithm, ticket.pwd.data, ticket.pwd.len,&hmac_is_valid)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to validate request signature: %s" , hawkc_get_error(&hawkc_ctx));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if(!hmac_is_valid) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid signature in %V" ,&(r->headers_in.authorization->value) );
		return ngx_dlg_auth_send_simple_401(r);
	}

	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Hawk access using token; client=%V, expires=fixme" , &(ticket.client) );

	/* check scopes */

	/* check nonce */

	/* check ts */

	return NGX_OK;
}

/*
 * FIXME
 */
static ngx_int_t ngx_dlg_auth_remove_authorization_header(ngx_http_request_t *r) {

	ngx_uint_t nelts;
	size_t size;
	int i;

	nelts = r->headers_in.headers.part.nelts;
	size = r->headers_in.headers.size;

  	for(i=0; i < nelts; i++) {
   		void *elt;
   		ngx_table_elt_t *data;
   		elt = r->headers_in.headers.part.elts + (i * size);
   		data = (ngx_table_elt_t*)elt;

   		if(data->key.len == 13 && memcmp(data->lowcase_key,"authorization",13) == 0) {
   			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, " Removing Authorization request header");
   			memcpy(data->key.data,"X-",2);
   			memcpy(data->lowcase_key,"x-",2);
   			r->headers_in.authorization = NULL;
   			break;
   		}
   	}
    return NGX_OK;
}


static ngx_int_t
ngx_dlg_auth_send_simple_401(ngx_http_request_t *r) {
    	ngx_str_t challenge;

    	r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.www_authenticate == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.www_authenticate->hash = 1;
        ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");

        challenge.len = 17; /* sizeof("Hawk realm=\"\"") - 1 + realm->len; */
        challenge.data = ngx_pnalloc(r->pool, challenge.len);
        if (challenge.data == NULL) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_cpymem(challenge.data, "Hawk realm=\"Test\"",17);

/*
        p = ngx_cpymem(challenge.data, "Hawk realm=\"",12);
        p = ngx_cpymem(p, realm->data, realm->len);
        p = ngx_cpymem(p, "\"", sizeof("\""));
        */

        r->headers_out.www_authenticate->value = challenge;

        return NGX_HTTP_UNAUTHORIZED;
}



static ngx_int_t
ngx_dlg_auth_handler(ngx_http_request_t *r)
{
    ngx_http_dlg_auth_loc_conf_t  *alcf;
    ngx_str_t                        realm;
    ngx_str_t                        password;

    ngx_table_elt_t             *data;
        ngx_list_part_t             *new, *curr;
        int i;
        void *elt;
        int size;
        ngx_int_t rc;



    alcf = ngx_http_get_module_loc_conf(r, nginx_dlg_auth_module);

    if (alcf->realm == NULL) {
        return NGX_DECLINED;
    }
    if (alcf->password == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->password, &password) != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->headers_in.authorization == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no auth header");
            //FIXME: send c
            return ngx_dlg_auth_send_simple_401(r);
        }

    if( (rc =  ngx_dlg_auth_authenticate(r,password)) != NGX_OK) {
    	return rc;
    }


    ngx_dlg_auth_remove_authorization_header(r);

    return NGX_OK;
}

void get_host_and_port(ngx_str_t host_header, ngx_str_t *host, ngx_str_t *port) {
		u_char *p;
		int i;


		port->len = 0;
		p = host_header.data;
		host->data = p;
		i=0;
		while(i < host_header.len && *p != ':') {
			p++;
			i++;
		}
		host->len = i;
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

