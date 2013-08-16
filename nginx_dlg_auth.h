#ifndef NGX_HTTP_DLG_H
#define NGX_HTTP_DLG_H

#include <time.h>
#include <stddef.h>
#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_palloc.h>
#include <ngx_crypt.h>
#include <hawkc.h>
#include <ciron.h>
#include "ticket.h"

typedef struct {
	ngx_str_t client;
	ngx_str_t user;
	ngx_str_t owner;
	ngx_str_t expires;
	ngx_str_t clockskew;
} ngx_http_dlg_auth_ctx_t;

ngx_module_t  nginx_dlg_auth_module;

#endif /* NGX_HTTP_DLG_H */




