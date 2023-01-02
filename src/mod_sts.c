/***************************************************************************
 *
 * Copyright (C) 2018-2023 - ZmartZone Holding BV - www.zmartzone.eu
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
		if ((status_code >= 400) && (status_code < 500)) {
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

OAUTH2_APACHE_CMD_ARGS1(sts, oauth2_sts_cfg_t, passphrase,
			oauth2_crypto_passphrase_set, NULL)
OAUTH2_APACHE_CMD_ARGS2(sts, oauth2_sts_cfg_t, cache, oauth2_cfg_set_cache,
			NULL)
OAUTH2_APACHE_CMD_ARGS2(sts, oauth2_sts_cfg_t, accept_source_token_in,
			sts_cfg_set_accept_source_token_in, cfg)
OAUTH2_APACHE_CMD_ARGS2(sts, oauth2_sts_cfg_t, pass_target_token_in,
			sts_cfg_set_pass_target_token_in, cfg)
OAUTH2_APACHE_CMD_ARGS3(sts, oauth2_sts_cfg_t, exchange, sts_cfg_set_exchange,
			cfg)

// clang-format off

static const command_rec OAUTH2_APACHE_COMMANDS(sts)[] = {

	OAUTH2_APACHE_CMD_ARGS(sts, 1,
		STSCryptoPassphrase,
		passphrase,
		"Set the crypto passphrase"),

	OAUTH2_APACHE_CMD_ARGS(sts, 12,
		STSCache,
		cache,
		"Set the cache type and options"),

	OAUTH2_APACHE_CMD_ARGS(sts, 12,
		STSAcceptSourceTokenIn,
		accept_source_token_in,
		"Configures in which format tokens can be presented."),

	OAUTH2_APACHE_CMD_ARGS(sts, 12,
		STSPassTargetTokenIn,
		pass_target_token_in,
		"Configures in which way the target token is passed to the application."),

	OAUTH2_APACHE_CMD_ARGS(sts, 23,
		STSExchange,
		exchange,
		"Configures the token exchange protocol and parameters."),

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
