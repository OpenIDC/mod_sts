/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include <oauth2/apache.h>
#include <oauth2/cfg.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/proto.h>
#include <oauth2/sts.h>
#include <oauth2/util.h>

#include <httpd.h>

#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>

OAUTH2_APACHE_LOG(sts)

/*
static int sts_config_merged_vhost_configs_exist(server_rec *s)
{
	sts_server_config *cfg = NULL;
	int rc = FALSE;
	while (s != NULL) {
		cfg = ap_get_module_config(s->module_config, &sts_module);
		if (cfg->merged) {
			rc = TRUE;
			break;
		}
		s = s->next;
	}
	return rc;
}

int sts_config_check_vhost_config(oauth2_log_t *log, apr_pool_t *pool,
				  server_rec *s)
{
	sts_server_config *cfg =
	    ap_get_module_config(s->module_config, &sts_module);
	int rc = OK;
	int mode = (cfg->mode == STS_CONFIG_POS_INT_UNSET)
		       ? STS_CONFIG_DEFAULT_STS_MODE
		       : cfg->mode;
	switch (mode) {
	case STS_CONFIG_MODE_WSTRUST:
		rc = sts_wstrust_config_check_vhost(cfg->log, pool, s, cfg);
		break;
	case STS_CONFIG_MODE_ROPC:
		rc = sts_ropc_config_check_vhost(cfg->log, pool, s, cfg);
		break;
	case STS_CONFIG_MODE_OTX:
		rc = sts_otx_config_check_vhost(cfg->log, pool, s, cfg);
		break;
	default:
		oauth2_error(log, "STS mode is set to unsupported value: %d",
			  mode);
		rc = HTTP_INTERNAL_SERVER_ERROR;
		break;
	}
	return rc;
}

static int sts_config_check_merged_vhost_configs(oauth2_log_t *log,
						 apr_pool_t *pool,
						 server_rec *s)
{
	sts_server_config *cfg = NULL;
	int rc = OK;
	while (s != NULL) {
		cfg = ap_get_module_config(s->module_config, &sts_module);
		if (cfg->merged) {
			rc = sts_config_check_vhost_config(log, pool, s);
			if (rc != OK) {
				break;
			}
		}
		s = s->next;
	}
	return rc;
}
*/

/*
 * Apache has a base vhost that true vhosts derive from.
 * There are two startup scenarios:
 *
 * 1. Only the base vhost contains STS settings.
 *    No server configs have been merged.
 *    Only the base vhost needs to be checked.
 *
 * 2. The base vhost contains zero or more STS settings.
 *    One or more vhosts override these.
 *    These vhosts have a merged config.
 *    All merged configs need to be checked.
 */

/*
if (!sts_config_merged_vhost_configs_exist(s)) {
	return sts_config_check_vhost_config(cfg->log, pool, s);
}
return sts_config_check_merged_vhost_configs(cfg->log, pool, s);
*/

/*
#define STS_USERDATA_POST_PARAMS_KEY "sts_userdata_post_params"

static bool sts_userdata_set_post_param(oauth2_log_t *log, request_rec *r,
					const char *post_param_name,
					const char *post_param_value)
{

	char *userdata_post_params = NULL;
	oauth2_nv_list_t *list = oauth2_nv_list_init(log);
	oauth2_nv_list_add(log, list, post_param_name, post_param_value);
	userdata_post_params = oauth2_http_url_form_encode(log, list);
	apr_pool_userdata_set(apr_pstrdup(r->pool, userdata_post_params),
			      STS_USERDATA_POST_PARAMS_KEY, NULL, r->pool);
	oauth2_mem_free(userdata_post_params);
	return true;
}

bool oauth2_apache_http_read_post(oauth2_log_t *log, request_rec *r,
			       oauth2_nv_list_t **list);

static const char stsFilterName[] = "sts_filter_in_filter";

static void sts_filter_in_insert_filter(request_rec *r)
{

	if (ap_is_initial_req(r) == 0)
		return;

	if (sts_get_enabled(r) != 1)
		return;

	char *userdata_post_params = NULL;
	apr_pool_userdata_get((void **)&userdata_post_params,
			      STS_USERDATA_POST_PARAMS_KEY, r->pool);
	if (userdata_post_params == NULL)
		return;

	ap_add_input_filter(stsFilterName, NULL, r, r->connection);
}

typedef struct sts_filter_in_context {
	apr_bucket_brigade *pbbTmp;
	apr_size_t nbytes;
} sts_filter_in_context;

static apr_status_t sts_filter_in_filter(ap_filter_t *f,
					 apr_bucket_brigade *brigade,
					 ap_input_mode_t mode,
					 apr_read_type_e block,
					 apr_off_t nbytes)
{
	sts_filter_in_context *ctx = NULL;
	apr_bucket *b_in = NULL, *b_out = NULL;
	char *buf = NULL;
	apr_status_t rc = APR_SUCCESS;
	char *userdata_post_params = NULL;

	oauth2_apache_request_context_t *actx =
	    oauth2_apache_request_context_get(f->r);

	apr_pool_userdata_get((void **)&userdata_post_params,
			      STS_USERDATA_POST_PARAMS_KEY, f->r->pool);

	if (!(ctx = f->ctx)) {
		f->ctx = ctx = apr_palloc(f->r->pool, sizeof *ctx);
		ctx->pbbTmp = apr_brigade_create(
		    f->r->pool, f->r->connection->bucket_alloc);
		ctx->nbytes = 0;
	}

	if (APR_BRIGADE_EMPTY(ctx->pbbTmp)) {
		rc = ap_get_brigade(f->next, ctx->pbbTmp, mode, block, nbytes);

		if (mode == AP_MODE_EATCRLF || rc != APR_SUCCESS)
			return rc;
	}

	while (!APR_BRIGADE_EMPTY(ctx->pbbTmp)) {

		b_in = APR_BRIGADE_FIRST(ctx->pbbTmp);

		if (APR_BUCKET_IS_EOS(b_in)) {

			APR_BUCKET_REMOVE(b_in);

			// TODO: this relies on the precondition that one post
			// parameter is
			// already there...
			if (ctx->nbytes > 0) {

				// we wouldn't be filtering if there wasn't any
				// data to add so
				// userdata_post_params != NULL
				buf = apr_psprintf(f->r->pool, "&%s",
						   userdata_post_params);
				b_out = apr_bucket_heap_create(
				    buf, strlen(buf), 0,
				    f->r->connection->bucket_alloc);

				APR_BRIGADE_INSERT_TAIL(brigade, b_out);

				oauth2_debug(actx->log,
					  "## adding: %lu post data to "
					  "existing length: %ld",
					  strlen(buf), ctx->nbytes);

				ctx->nbytes += strlen(buf);

				if (oauth2_http_hdr_in_content_length_get(
					actx->log, actx->request) != NULL)
					oauth2_http_hdr_in_content_length_set(
					    actx->log, actx->request,
					    ctx->nbytes);

				// we can have multiple APR_BUCKET_IS_EOS coming
				// in
				// so make sure we add our target token only
				// once
				ctx->nbytes = 0;
			}

			APR_BRIGADE_INSERT_TAIL(brigade, b_in);

			break;
		}

		APR_BUCKET_REMOVE(b_in);
		APR_BRIGADE_INSERT_TAIL(brigade, b_in);
		ctx->nbytes += b_in->length;
	}

	return rc;
}
*/

static int sts_check_access_handler(request_rec *r)
{
	oauth2_sts_cfg_t *cfg = NULL;
	oauth2_apache_request_ctx_t *ctx = NULL;
	char *source_token = NULL;
	int rv = DECLINED;
	oauth2_http_status_code_t status_code = 0;

	cfg = ap_get_module_config(r->per_dir_config, &sts_module);
	ctx = OAUTH2_APACHE_REQUEST_CTX(r, sts);

	oauth2_debug(ctx->log, "enter: \"%s?%s\", ap_is_initial_req(r)=%d",
		     r->parsed_uri.path, r->args, ap_is_initial_req(r));

	if (ap_is_initial_req(r) == 0)
		goto end;

	if (sts_cfg_get_type(cfg) == STS_TYPE_DISABLED) {
		oauth2_debug(ctx->log, "disabled");
		goto end;
	}

	if (sts_request_handler(ctx->log, cfg, ctx->request, r->user,
				&source_token,
				&oauth2_apache_server_callback_funcs, ctx->r,
				&status_code) == false) {
		if (status_code < 500) {
			rv = oauth2_apache_return_www_authenticate(
			    sts_accept_source_token_in_get(NULL, cfg), ctx,
			    status_code >= 500 ? status_code
					       : HTTP_UNAUTHORIZED,
			    "invalid_token", "Token could not be swapped.");
		} else {
			rv = status_code;
		}
		goto end;
	}

	rv = OK;

	// if the source token comes from an env var, that may not have been set
	// until the fixup handler runs, so we'll indicated that we want to run
	// at fixup time

	//	if ((rc == DECLINED) && (source_token == NULL) &&
	//	    (dir_cfg->accept_source_token_in & STS_CONFIG_TOKEN_ENVVAR))
	//{ 		apr_pool_userdata_set((const void *)1,
	// fixup_userdata_key, apr_pool_cleanup_null, r->pool);
	//	}

	if (sts_get_pass_target_token_in(cfg) & OAUTH2_CFG_TOKEN_IN_HEADER)
		oauth2_apache_request_header_set(
		    ctx->log, ctx->r,
		    sts_get_pass_target_token_in_hdr_name(cfg),
		    oauth2_http_request_header_get(
			ctx->log, ctx->request,
			sts_get_pass_target_token_in_hdr_name(cfg)));
	if (sts_get_pass_target_token_in(cfg) & OAUTH2_CFG_TOKEN_IN_COOKIE)
		oauth2_apache_request_header_set(
		    ctx->log, ctx->r, OAUTH2_HTTP_HDR_COOKIE,
		    oauth2_http_request_header_cookie_get(ctx->log,
							  ctx->request));
	if (sts_get_pass_target_token_in(cfg) & OAUTH2_CFG_TOKEN_IN_BASIC)
		oauth2_apache_request_header_set(
		    ctx->log, ctx->r, OAUTH2_HTTP_HDR_AUTHORIZATION,
		    oauth2_http_request_header_get(
			ctx->log, ctx->request, OAUTH2_HTTP_HDR_AUTHORIZATION));
	// if (sts_get_pass_target_token_in(cfg->cfg) &
	// OAUTH2_CFG_TOKEN_IN_QUERY)

end:

	if (source_token)
		oauth2_mem_free(source_token);

	oauth2_debug(ctx->log, "leave: %d", rv);

	return rv;
}

OAUTH2_APACHE_HANDLERS(sts)

#define STS_CFG_FUNC_ARGS(nargs, member)                                       \
	OAUTH2_APACHE_CMD_ARGS##nargs(sts_cfg, member)

// const char *apache_sts_cfg_set_exchange() {
//	return NULL;
//}

STS_CFG_FUNC_ARGS(23, exchange)
STS_CFG_FUNC_ARGS(2, cache)
STS_CFG_FUNC_ARGS(1, passphrase)
STS_CFG_FUNC_ARGS(2, accept_source_token_in)
STS_CFG_FUNC_ARGS(2, pass_target_token_in)

// clang-format off
#define STS_CFG_CMD_ARGS(nargs, cmd, member, desc) \
	AP_INIT_TAKE##nargs( \
		cmd, \
		apache_sts_cfg_set_##member, \
		NULL, \
		RSRC_CONF | ACCESS_CONF | OR_AUTHCFG, \
		desc)

static const command_rec OAUTH2_APACHE_COMMANDS(sts)[] = {

	STS_CFG_CMD_ARGS(1,
			STSCryptoPassphrase,
		passphrase,
		"Set the crypto passphrase"),

	STS_CFG_CMD_ARGS(23,
		STSExchange,
		exchange,
		"Configures the token exchange protocol and parameters."),

	STS_CFG_CMD_ARGS(12,
		STSCache,
		cache,
		"Set the cache type and options"),

	STS_CFG_CMD_ARGS(12,
		STSAcceptSourceTokenIn,
		accept_source_token_in,
		"Configures in which format tokens can be presented."),

	STS_CFG_CMD_ARGS(12,
		STSPassTargetTokenIn,
		pass_target_token_in,
		"Configures in which way the target token is passed to the application."),

	{ NULL }

};

static void OAUTH2_APACHE_REGISTER_HOOKS(sts)(apr_pool_t *p)
{
	static const char *const aszPre[] = {"mod_auth_openidc.c", "mod_oauth2.c", NULL};
	ap_hook_post_config(OAUTH2_APACHE_POST_CONFIG(sts), NULL, NULL, APR_HOOK_MIDDLE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_fixups(sts_check_access_handler, aszPre, NULL, APR_HOOK_LAST);
#else
	ap_hook_fixups(sts_check_access_handler, aszPre, NULL, APR_HOOK_LAST);
#endif
	/*
	ap_hook_insert_filter(sts_filter_in_insert_filter, NULL, NULL,
			      APR_HOOK_MIDDLE);
	ap_register_input_filter(stsFilterName, sts_filter_in_filter, NULL,
				 AP_FTYPE_RESOURCE);
	*/
}

OAUTH2_APACHE_MODULE_DECLARE(
	sts,
	sts_cfg
)
// clang-format on
