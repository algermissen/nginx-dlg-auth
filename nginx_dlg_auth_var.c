/*
#include <time.h>
#include <stddef.h>
#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
*/

#include "nginx_dlg_auth.h"

/*
 * Fill client variable from module per request context.
 */
static ngx_int_t ngx_http_dlg_auth_client_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_dlg_auth_ctx_t *ctx;

	if( (ctx = ngx_http_get_module_ctx(r, nginx_dlg_auth_module)) == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}
	if(ctx->client.len == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->data = ctx->client.data;
	v->len = ctx->client.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

/*
 * Fill expires variable from module per request context.
 */
static ngx_int_t ngx_http_dlg_auth_expires_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_dlg_auth_ctx_t *ctx;

	if( (ctx = ngx_http_get_module_ctx(r, nginx_dlg_auth_module)) == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}
	if(ctx->expires.len == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->data = ctx->expires.data;
	v->len = ctx->expires.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}

/*
 * Fill clockskew variable from module per request context.
 */
static ngx_int_t ngx_http_dlg_auth_clockskew_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_dlg_auth_ctx_t *ctx;

	if( (ctx = ngx_http_get_module_ctx(r, nginx_dlg_auth_module)) == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}
	if(ctx->clockskew.len == 0) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->data = ctx->clockskew.data;
	v->len = ctx->clockskew.len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	return NGX_OK;
}


/*
 * This array defines our variables. They will be added to the global set of
 * variables in preconfiguration phase by hooking the function below into
 * the module config at that phase.
 */
static ngx_http_variable_t  ngx_dlg_auth_vars[] = {

    { ngx_string("dlg_auth_client"), NULL,
      ngx_http_dlg_auth_client_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("dlg_auth_expires"), NULL,
      ngx_http_dlg_auth_expires_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("dlg_auth_clockskew"), NULL,
      ngx_http_dlg_auth_clockskew_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};



/*
 * Add our variables to the main NGINX configuration.
 */
ngx_int_t ngx_http_auth_dlg_add_variables(ngx_conf_t *cf) {
	ngx_http_variable_t  *var, *v;

	for (v = ngx_dlg_auth_vars; v->name.len; v++) {
		if( (var = ngx_http_add_variable(cf, &v->name, v->flags)) == NULL) {
			return NGX_ERROR;
		}
		var->get_handler = v->get_handler;
		var->data = v->data;
	}
	return NGX_OK;
}




