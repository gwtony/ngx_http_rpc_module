#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *ngx_http_rpc_create_conf(ngx_conf_t *cf);
static char *ngx_http_rpc_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_rpc_preconf(ngx_conf_t *cf);
static ngx_int_t rpc_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_rpc_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rpc_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static char *ngx_http_rpc_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t rpc_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_rpc_commands[] = {
    { ngx_string("rpc_pass"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1|NGX_CONF_TAKE2,
      ngx_http_rpc_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_variable_t rpc_variables[] = {
    { ngx_string("rpc_result"),
        NULL, rpc_get,
        0,
        0,
        0
    },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

typedef struct {
	ngx_str_t uri;
	ngx_str_t key;  
} ngx_http_rpc_conf_t; 

typedef struct {
    ngx_uint_t          done;
    ngx_uint_t          status;
    ngx_http_request_t *subrequest;
	ngx_str_t           result
} ngx_http_rpc_ctx_t;

static ngx_http_module_t  ngx_http_rpc_module_ctx = {
    ngx_http_rpc_preconf,       /* preconfiguration */
    ngx_http_rpc_init,          /* postconfiguration */

    NULL,                        /* create main configuration */
    NULL,                        /* init main configuration */

    NULL,                        /* create server configuration */
    NULL,                        /* merge server configuration */

    ngx_http_rpc_create_conf,   /* create location configuration */
    ngx_http_rpc_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_rpc_module = {
    NGX_MODULE_V1,
    &ngx_http_rpc_module_ctx,    /* module context */
    ngx_http_rpc_commands,       /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
	NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_rpc_preconf(ngx_conf_t *cf)
{
	if (rpc_add_variables(cf) == NGX_OK) {
		return NGX_OK;
	}
	return NGX_ERROR;
}

static ngx_int_t rpc_add_variables(ngx_conf_t *cf)
{
	int i;
	ngx_http_variable_t *var;

	for (i=0; rpc_variables[i].name.len>0; ++i) {
		var = ngx_http_add_variable(cf, &rpc_variables[i].name, rpc_variables[i].flags);
		if (var==NULL) {
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "rpc add variable '%s' failed.", rpc_variables[i].name.data);

			return NGX_ERROR;
		}

		var->set_handler = rpc_variables[i].set_handler;
		var->get_handler = rpc_variables[i].get_handler;
		var->data = rpc_variables[i].data;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_rpc_handler(ngx_http_request_t *r)
{
    ngx_table_elt_t               *h, *ho;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_http_rpc_ctx_t   *ctx;
    ngx_http_rpc_conf_t  *rcf;
	ngx_list_part_t       *part;
	ngx_table_elt_t       *header;

    rcf = ngx_http_get_module_loc_conf(r, ngx_http_rpc_module);

    if (rcf->uri.len == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rpc handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_rpc_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return NGX_AGAIN;
        }

        /* return appropriate status */
        if (ctx->status == NGX_HTTP_FORBIDDEN &&
			ctx->status == NGX_HTTP_UNAUTHORIZED) {
            return ctx->status;
        }

        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
			int i;
			part = &ctx->subrequest->headers_out.headers.part;
			header = part->elts;
			for (i = 0; /* void */; i++) {

				if (i >= part->nelts) {
					if (part->next == NULL) {
						break;
					}

					part = part->next;
					header = part->elts;
					i = 0;
				}

				if (header[i].hash == 0) {
					continue;
				}

				//for debug
				if (header[i].key.len > 0) {
        			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "key is %V", &header[i].key);
				}
				if (header[i].value.len > 0) {
        			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "value is %V", &header[i].value);
				}

				//TODO: better way
				if ((header[i].key.len == rcf->key.len) && 
					(ngx_strncmp(header[i].key.data, rcf->key.data, rcf->key.len) == 0)) {
					ctx->result.data = header[i].value.data;
					ctx->result.len = header[i].value.len;
					break;
				}
			}
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "rpc request unexpected status: %ui", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rpc_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_rpc_done;
    ps->data = ctx;

    if (ngx_http_subrequest(r, &rcf->uri, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    ngx_http_set_ctx(r, ctx, ngx_http_rpc_module);

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_rpc_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_rpc_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rpc done s:%ui", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static void *
ngx_http_rpc_create_conf(ngx_conf_t *cf)
{
    ngx_http_rpc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rpc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_rpc_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rpc_conf_t *prev = parent;
    ngx_http_rpc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->uri, prev->uri, "");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rpc_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_rpc_handler;
	

    return NGX_OK;
}

static char *
ngx_http_rpc_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	int 				  i;
    ngx_str_t            *value;
    ngx_http_rpc_conf_t *rcf = conf;

    if (rcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

	for (i = 1; i < cf->args->nelts; i++) {
		if (ngx_strncmp(value[i].data, "off", 3) == 0) {
			rcf->uri.len = 0;
			rcf->uri.data = (u_char *) "";

			return NGX_CONF_OK;
		}
		if (ngx_strncmp(value[i].data, "/", 1) == 0) {
			rcf->uri = value[i];
			continue;
		}

		if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
			rcf->key.len = value[i].len - 4;
			rcf->key.data = value[i].data + 4;
			continue;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t rpc_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_rpc_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_rpc_module);

    if (ctx != NULL) {
        if (ctx->done) {
			v->valid = 1;
			v->no_cacheable = 0;
			v->not_found = 0;
			v->data = (void*)ctx->result.data;
			v->len = ctx->result.len;
			return NGX_OK;
		}
	}
	v->valid = 0;
	v->no_cacheable = 0;
	v->not_found = 1;
	v->data = NULL;
	v->len = 0;
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "rpc result not found");
	return NGX_ERROR;
}
