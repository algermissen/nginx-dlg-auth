#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#include <hawkc.h>

typedef struct {
    ngx_str_t                 passwd;
} ngx_http_dlg_auth_ctx_t;


typedef struct {
    ngx_http_complex_value_t  *realm;
} ngx_http_dlg_auth_loc_conf_t;



static ngx_int_t ngx_http_dlg_auth_init(ngx_conf_t *cf);
static void *ngx_http_dlg_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dlg_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_dlg_auth_handler(ngx_http_request_t *r);

static ngx_int_t ngx_dlg_auth_remove_authorization_header(ngx_http_request_t *r);
static ngx_int_t ngx_dlg_auth_send_simple_401(ngx_http_request_t *r);


static ngx_command_t ngx_dlg_auth_commands[] = {

	{ ngx_string("dlg_auth"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
	                       |NGX_CONF_TAKE1,
	  ngx_http_set_complex_value_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_dlg_auth_loc_conf_t, realm),
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
/*
    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }
    */

    return NGX_CONF_OK;
}


static ngx_int_t ngx_dlg_auth_authenticate(ngx_http_request_t *r) {

	HawkcError e;
	struct HawkcContext ctx;
	int is_valid;
	char pwd[] = "test";

	hawkc_context_init(&ctx);
	hawkc_context_set_method(&ctx,r->method_name.data, r->method_name.len);
	hawkc_context_set_path(&ctx,r->uri.data, r->uri.len);
	hawkc_context_set_host(&ctx,r->headers_in.host->value.data, r->headers_in.host->value.len);
	hawkc_context_set_port(&ctx,80); /* FIXME */

	/*
	howkc_context_set_userdata(&ctx,nonce_pool);
	*/

	if( (e = hawkc_parse_authorization_header(&ctx,r->headers_in.authorization->value.data, r->headers_in.authorization->value.len)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to parse Authorization header: %s" , hawkc_get_error(&ctx));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	if( (e = hawkc_validate_hmac(&ctx, SHA_1, (unsigned char *)pwd, strlen(pwd),&is_valid)) != HAWKC_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unable to validate request signature: %s" , hawkc_get_error(&ctx));
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	if(!is_valid) {
		return ngx_dlg_auth_send_simple_401(r);

	}

	/* check nonce */

	/* check ts */

	return NGX_OK;
}
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
   			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Removing Authorization request header");
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
    ngx_http_dlg_auth_ctx_t       *ctx;


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

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, nginx_dlg_auth_module);


    if (!ctx) {
    	/*
        return ngx_http_auth_basic_crypt_handler(r, ctx, &ctx->passwd,
                                                 &realm);
                                                 */
    	;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "got ctx");

    if (r->headers_in.authorization == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no auth header");
            //FIXME: send c
            return ngx_dlg_auth_send_simple_401(r);
        }

    if( (rc =  ngx_dlg_auth_authenticate(r)) != NGX_OK) {
    	return rc;
    }


    ngx_dlg_auth_remove_authorization_header(r);

    return NGX_OK;
}


#if 0
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "got auth header");

    /*
     * headers is ngx_list_t
     */
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "2xx%d" , r->headers_in.headers.size);
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "3xx%d" , r->headers_in.headers.part.nelts);
    	size = r->headers_in.headers.size;

    	for(i=0;i<r->headers_in.headers.part.nelts;i++) {
    		char buf[1024];
    		memset(buf,0,1024);
    		elt = r->headers_in.headers.part.elts + (i * size);
    		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "4x01");
    		data = (ngx_table_elt_t*)elt;
    		strncpy(buf,data->key.data, data->key.len);
    		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "4xx02 %s" , buf);

    		strncpy(buf,data->lowcase_key, data->key.len);
    		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "4xx02 %s" , buf);
    		if(r->headers_in.authorization == data) {
    			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IT IS THE POINTER!");

    		}
    		if(memcmp(buf,"authorization",13) == 0) {
    			memcpy(data->key.data,"aaaaaaaaaaaaa",13);
    			memcpy(data->lowcase_key,"aaaaaaaaaaaaa",13);
    		}
    	}
    	r->headers_in.authorization = NULL;

    	/*
    curr = r->headers_in.headers.last;
    while(curr != NULL) {

    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "xx");
    	curr = curr->next;
    }
    */
#endif
