#ifndef NGX_HTTP_DLG_AUTH_VAR_H
#define NGX_HTTP_DLG_AUTH_VAR_H

#include <ngx_config.h>
#include <ngx_core.h>
/*
#include <ngx_http.h>
*/

/*
 * This must be hooked into module struct as preconfiguration phase handler.
 */
ngx_int_t ngx_http_auth_dlg_add_variables(ngx_conf_t *cf);


#endif /* NGX_HTTP_DLG_AUTH_VAR_H */
