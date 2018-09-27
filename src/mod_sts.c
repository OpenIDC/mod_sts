/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2017-2018 ZmartZone IAM
 * All rights reserved.
 *
 *      ZmartZone IAM
 *      info@zmartzone.eu
 *      http://www.zmartzone.eu
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

// TODO: is the fixup handler the right place for the sts_handler
//       or should we only handle source/target envvar stuff there?
// TODO: strip the source token from the propagated request? (optionally?)
//       FWIW: the authorization header will be overwritten
// TODO: client authentication options for all(!) STS methods
#include <httpd.h>
#include <http_config.h>
#include <http_request.h>
#include <http_protocol.h>
#include <http_core.h>

#include <apr_hooks.h>
#include <apr_optional.h>
#include <apr_base64.h>
#include <apr_lib.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "mod_sts.h"

module AP_MODULE_DECLARE_DATA sts_module;

#define STS_CONFIG_POS_INT_UNSET                   -1
#define STS_CONFIG_DEFAULT_ENABLED                 1

#define STS_CONFIG_DEFAULT_WSTRUST_STS_URL         "https://localhost:9031/pf/sts.wst"
#define STS_CONFIG_DEFAULT_WSTRUST_APPLIES_TO      "localhost:default:entityId"
#define STS_CONFIG_DEFAULT_WSTRUST_TOKEN_TYPE      "urn:bogus:token"
//#define STS_CONFIG_DEFAULT_WSTRUST_TOKEN_TYPE      "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"

#define STS_CONFIG_DEFAULT_WSTRUST_VALUE_TYPE      "urn:pingidentity.com:oauth2:grant_type:validate_bearer"
#define STS_CONFIG_DEFAULT_WSTRUST_ACTION          "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
#define STS_CONFIG_DEFAULT_WSTRUST_REQUEST_TYPE    "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
#define STS_CONFIG_DEFAULT_WSTRUST_KEY_TYPE        "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"

#define STS_CONFIG_DEFAULT_ROPC_TOKEN_ENDPOINT     "https://localhost:9031/as/token.oauth2"
#define STS_CONFIG_DEFAULT_ROPC_CLIENT_ID          "mod_sts"
#define STS_CONFIG_DEFAULT_ROPC_USERNAME           NULL

#define STS_CONFIG_DEFAULT_OAUTH_TX_ENDPOINT       "https://localhost:9031/as/token.oauth2"

#define STS_CONFIG_DEFAULT_CACHE_SHM_SIZE          2048
#define STS_CONFIG_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 4096 + 512 + 17

#define STS_CONFIG_DEFAULT_CACHE_EXPIRES_IN        300

#define STS_CONFIG_MODE_WSTRUST_STR                "wstrust"
#define STS_CONFIG_MODE_WSTRUST                    0
#define STS_CONFIG_MODE_ROPC_STR                   "ropc"
#define STS_CONFIG_MODE_ROPC                       1
#define STS_CONFIG_MODE_OAUTH_TX_STR               "oauth"
#define STS_CONFIG_MODE_OAUTH_TX                   2

#define STS_CONFIG_DEFAULT_STS_MODE                STS_CONFIG_MODE_WSTRUST

#define STS_CACHE_SECTION                          "sts"

#define STS_CONFIG_DEFAULT_SSL_VALIDATION          1
#define STS_CONFIG_DEFAULT_HTTP_TIMEOUT            20

#define STS_CONFIG_TOKEN_ENVVAR_STR                "environment"
static const int STS_CONFIG_TOKEN_ENVVAR         = 1;
#define STS_CONFIG_TOKEN_HEADER_STR                "header"
static const int STS_CONFIG_TOKEN_HEADER         = 2;
#define STS_CONFIG_TOKEN_QUERY_STR                 "query"
static const int STS_CONFIG_TOKEN_QUERY          = 4;
#define STS_CONFIG_TOKEN_COOKIE_STR                "cookie"
static const int STS_CONFIG_TOKEN_COOKIE         = 8;

#define STS_DEFAULT_ACCEPT_SOURCE_TOKEN_IN         (STS_CONFIG_TOKEN_ENVVAR | STS_CONFIG_TOKEN_HEADER)
#define STS_DEFAULT_SET_TARGET_TOKEN_IN            (STS_CONFIG_TOKEN_ENVVAR | STS_CONFIG_TOKEN_COOKIE)

#define STS_HEADER_AUTHORIZATION_BEARER            "Bearer"

#define STS_CONFIG_TOKEN_OPTION_SEPARATOR          ":"
#define STS_CONFIG_TOKEN_OPTION_NAME               "name"
#define STS_CONFIG_TOKEN_OPTION_TYPE               "type"

#define STS_SOURCE_TOKEN_HEADER_NAME_DEFAULT       STS_HEADER_AUTHORIZATION
#define STS_SOURCE_TOKEN_HEADER_TYPE_DEFAULT       STS_HEADER_AUTHORIZATION_BEARER
#define STS_SOURCE_TOKEN_COOKIE_NAME_DEFAULT       "PA.global"
#define STS_SOURCE_TOKEN_ENVVAR_NAME_DEFAULT       "OIDC_access_token"
#define STS_SOURCE_TOKEN_QUERY_PARAMNAME_DEFAULT   "access_token"

#define STS_TARGET_TOKEN_COOKIE_NAME_DEFAULT       "sts_token"
#define STS_TARGET_TOKEN_ENVVAR_NAME_DEFAULT       "MOD_STS_TARGET_TOKEN"
#define STS_TARGET_TOKEN_QUERY_PARAM_NAME_DEFAULT  "access_token"
#define STS_TARGET_TOKEN_HEADER_NAME_DEFAULT       STS_HEADER_AUTHORIZATION
#define STS_TARGET_TOKEN_HEADER_TYPE_DEFAULT       STS_HEADER_AUTHORIZATION_BEARER

#define STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC      "client_secret_basic"
#define STS_ENDPOINT_AUTH_CLIENT_SECRET_POST       "client_secret_post"
#define STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT        "client_secret_jwt"
#define STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT          "private_key_jwt"
#define STS_ENDPOINT_AUTH_CLIENT_CERT              "client_cert"

static apr_status_t sts_cleanup_handler(void *data) {
	server_rec *s = (server_rec *) data;
	sts_sinfo(s, "%s - shutdown", NAMEVERSION);

	server_rec *sp = (server_rec *) data;
	while (sp != NULL) {
		if (sts_cache_shm_destroy(sp) != APR_SUCCESS) {
			sts_serror(sp, "cache destroy function failed");
		}
		sp = sp->next;
	}

	return APR_SUCCESS;
}

static int sts_post_config_handler(apr_pool_t *pool, apr_pool_t *p1,
		apr_pool_t *p2, server_rec *s) {
	sts_sinfo(s, "%s - init", NAMEVERSION);
	apr_pool_cleanup_register(pool, s, sts_cleanup_handler,
			apr_pool_cleanup_null);

	server_rec *sp = s;
	while (sp != NULL) {
		if (sts_cache_shm_post_config(sp) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
		sp = sp->next;
	}

	return OK;
}

static void sts_child_init(apr_pool_t *p, server_rec *s) {
	while (s != NULL) {
		if (sts_cache_shm_child_init(p, s) != APR_SUCCESS) {
			sts_serror(s, "cfg->cache->child_init failed");
		}
		s = s->next;
	}
}

static const char *sts_set_string_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	return ap_set_string_slot(cmd, cfg, arg);
}

static const char *sts_set_int_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	return ap_set_int_slot(cmd, cfg, arg);
}

static const char *sts_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	return ap_set_flag_slot(cmd, cfg, arg);
}

static const char *sts_set_mode(cmd_parms *cmd, void *m, const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	if (strcmp(arg, STS_CONFIG_MODE_WSTRUST_STR) == 0) {
		cfg->mode = STS_CONFIG_MODE_WSTRUST;
		return NULL;
	}
	if (strcmp(arg, STS_CONFIG_MODE_ROPC_STR) == 0) {
		cfg->mode = STS_CONFIG_MODE_ROPC;
		return NULL;
	}
	if (strcmp(arg, STS_CONFIG_MODE_OAUTH_TX_STR) == 0) {
		cfg->mode = STS_CONFIG_MODE_OAUTH_TX;
		return NULL;
	}

	return "Invalid value: must be \"" STS_CONFIG_MODE_WSTRUST_STR "\", \"" STS_CONFIG_MODE_ROPC_STR "\" or \"" STS_CONFIG_MODE_OAUTH_TX_STR "\"";
}

static void sts_set_config_token_options(cmd_parms *cmd,
		apr_hash_t **config_token_options, const char *type, char *options) {
	if (options != NULL) {
		apr_table_t *params = apr_table_make(cmd->pool, 8);
		sts_util_read_form_encoded_params(cmd->pool, params, options);

		sts_sdebug(cmd->server, "parsed: %d bytes into %d elements",
				(int )strlen(options), apr_table_elts(params)->nelts);

		if (*config_token_options == NULL)
			*config_token_options = apr_hash_make(cmd->pool);
		apr_hash_set(*config_token_options, type,
				APR_HASH_KEY_STRING, params);
	}
}

static apr_hash_t *sts_get_allowed_methods(apr_pool_t *pool, char *allowed[]) {
	apr_hash_t *methods = apr_hash_make(pool);
	int i = 0;
	while (allowed[i] != NULL) {
		if (apr_strnatcmp(STS_CONFIG_TOKEN_ENVVAR_STR, allowed[i]) == 0) {
			apr_hash_set(methods, STS_CONFIG_TOKEN_ENVVAR_STR,
					APR_HASH_KEY_STRING, &STS_CONFIG_TOKEN_ENVVAR);
		} else if (apr_strnatcmp(STS_CONFIG_TOKEN_HEADER_STR, allowed[i])
				== 0) {
			apr_hash_set(methods, STS_CONFIG_TOKEN_HEADER_STR,
					APR_HASH_KEY_STRING, &STS_CONFIG_TOKEN_HEADER);
		} else if (apr_strnatcmp(STS_CONFIG_TOKEN_QUERY_STR, allowed[i]) == 0) {
			apr_hash_set(methods, STS_CONFIG_TOKEN_QUERY_STR,
					APR_HASH_KEY_STRING, &STS_CONFIG_TOKEN_QUERY);
		} else if (apr_strnatcmp(STS_CONFIG_TOKEN_COOKIE_STR, allowed[i])
				== 0) {
			apr_hash_set(methods, STS_CONFIG_TOKEN_COOKIE_STR,
					APR_HASH_KEY_STRING, &STS_CONFIG_TOKEN_COOKIE);
		}
		i++;
	}
	return methods;
}

static const char *sts_set_token_in(cmd_parms *cmd, const char *arg,
		char *allowed[], int *config_token, apr_hash_t **config_token_options) {
	char *rv = NULL;
	int i = 0;
	apr_hash_t *allowed_methods = sts_get_allowed_methods(cmd->pool, allowed);

	const char *method = apr_pstrdup(cmd->pool, arg);
	char *option = strstr(method, STS_CONFIG_TOKEN_OPTION_SEPARATOR);
	if (option != NULL) {
		*option = '\0';
		option++;
	}

	int *vp = apr_hash_get(allowed_methods, method, APR_HASH_KEY_STRING);
	if (vp != NULL) {
		if (*config_token == STS_CONFIG_POS_INT_UNSET)
			(*config_token) = (*vp);
		else
			(*config_token) |= (*vp);
		sts_set_config_token_options(cmd, config_token_options, method, option);
		return NULL;
	}

	rv = apr_psprintf(cmd->pool, "Invalid value for '%s': must be one of:",
			cmd->directive->directive);
	i = 0;
	while (allowed[i] != NULL) {
		rv = apr_psprintf(cmd->pool, "%s%s \"%s\"", rv,
				allowed[i + 1] == NULL ? " or" : i > 0 ? "," : "", allowed[i]);
		i++;
	}
	return apr_psprintf(cmd->pool, "%s.", rv);
}

static const char *sts_set_accept_source_token_in(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_dir_config *dir_cfg = (sts_dir_config *) m;
	static char *options[] = {
			STS_CONFIG_TOKEN_ENVVAR_STR,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_QUERY_STR,
			STS_CONFIG_TOKEN_COOKIE_STR,
			NULL };
	return sts_set_token_in(cmd, arg, options, &dir_cfg->accept_source_token_in,
			&dir_cfg->accept_source_token_in_options);
}

static const char *sts_set_set_target_token_in(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_dir_config *dir_cfg = (sts_dir_config *) m;
	static char *options[] = {
			STS_CONFIG_TOKEN_ENVVAR_STR,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_QUERY_STR,
			STS_CONFIG_TOKEN_COOKIE_STR,
			NULL };
	return sts_set_token_in(cmd, arg, options, &dir_cfg->set_target_token_in,
			&dir_cfg->set_target_token_in_options);
}

static int sts_get_http_timeout(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->http_timeout == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_HTTP_TIMEOUT;
	return cfg->http_timeout;
}

static const char * sts_get_wstrust_sts_url(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_sts_url == NULL)
		return STS_CONFIG_DEFAULT_WSTRUST_STS_URL;
	return cfg->wstrust_sts_url;
}

static const char * sts_get_wstrust_applies_to(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_applies_to == NULL)
		return STS_CONFIG_DEFAULT_WSTRUST_APPLIES_TO;
	return cfg->wstrust_applies_to;
}

static const char * sts_get_wstrust_token_type(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_token_type == NULL)
		return STS_CONFIG_DEFAULT_WSTRUST_TOKEN_TYPE;
	return cfg->wstrust_token_type;
}

static const char * sts_get_wstrust_value_type(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_value_type == NULL)
		return STS_CONFIG_DEFAULT_WSTRUST_VALUE_TYPE;
	return cfg->wstrust_value_type;
}

static const char * sts_get_ropc_token_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_token_endpoint == NULL)
		return STS_CONFIG_DEFAULT_ROPC_TOKEN_ENDPOINT;
	return cfg->ropc_token_endpoint;
}

static const char * sts_get_ropc_client_id(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_client_id == NULL)
		return STS_CONFIG_DEFAULT_ROPC_CLIENT_ID;
	return cfg->ropc_client_id;
}

static const char * sts_get_ropc_username(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_username == NULL)
		// return the client_id by default
		return sts_get_ropc_client_id(r);
	return cfg->ropc_username;
}

static const char * sts_get_oauth_token_exchange_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->oauth_token_exchange_endpoint == NULL)
		return STS_CONFIG_DEFAULT_OAUTH_TX_ENDPOINT;
	return cfg->oauth_token_exchange_endpoint;
}

static int sts_get_enabled(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->enabled == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_ENABLED;
	return dir_cfg->enabled;
}

static int sts_get_ssl_validation(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ssl_validation == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_SSL_VALIDATION;
	return cfg->ssl_validation;
}

static int sts_get_cache_expires_in(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->cache_expires_in == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_CACHE_EXPIRES_IN;
	return dir_cfg->cache_expires_in;
}

static int sts_get_mode(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->mode == STS_CONFIG_POS_INT_UNSET) {
		return STS_CONFIG_DEFAULT_STS_MODE;
	}
	return cfg->mode;
}

static int sts_get_accept_source_token_in(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->accept_source_token_in == STS_CONFIG_POS_INT_UNSET)
		return STS_DEFAULT_ACCEPT_SOURCE_TOKEN_IN;
	return dir_cfg->accept_source_token_in;
}

static int sts_get_set_target_token_in(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->set_target_token_in == STS_CONFIG_POS_INT_UNSET)
		return STS_DEFAULT_SET_TARGET_TOKEN_IN;
	return dir_cfg->set_target_token_in;
}

static const char * sts_get_resource(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	return dir_cfg->resource;
}

static const char *sts_get_config_token_option(request_rec *r,
		apr_hash_t *config_token_options, const char *type, const char *key,
		char *default_value) {
	const char *rv = NULL;
	if (config_token_options != NULL) {
		apr_table_t *options = (apr_table_t *) apr_hash_get(
				config_token_options, type,
				APR_HASH_KEY_STRING);
		if (options != NULL)
			rv = apr_table_get(options, key);
	}
	if (rv == NULL)
		rv = default_value;
	sts_debug(r, "%s:%s=%s", type, key, rv);
	return rv;
}

static char *sts_get_source_token_from_envvar(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *source_token = NULL;

	sts_debug(r, "enter");

	const char *envvar_name = sts_get_config_token_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_ENVVAR_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_SOURCE_TOKEN_ENVVAR_NAME_DEFAULT);
	source_token = apr_pstrdup(r->pool,
			apr_table_get(r->subprocess_env, envvar_name));

	if (source_token == NULL) {
		sts_debug(r, "no source found in %s subprocess environment variables",
				envvar_name);
	}
	return source_token;
}

static char *sts_get_source_token_from_header(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *source_token = NULL;

	sts_debug(r, "enter");

	const char *name = sts_get_config_token_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_SOURCE_TOKEN_HEADER_NAME_DEFAULT);
	const char *type = sts_get_config_token_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_TYPE,
			STS_SOURCE_TOKEN_HEADER_TYPE_DEFAULT);

	const char *auth_line = apr_table_get(r->headers_in, name);
	if (auth_line) {
		sts_debug(r, "%s header found", name);
		if ((type != NULL) && (apr_strnatcasecmp(type, "") != 0)) {
			char *scheme = ap_getword(r->pool, &auth_line, ' ');
			if (apr_strnatcasecmp(scheme, type) != 0) {
				sts_warn(r, "client used unsupported authentication scheme: %s",
						scheme);
				return NULL;
			}
		}
		while (apr_isspace(*auth_line))
			auth_line++;
		source_token = apr_pstrdup(r->pool, auth_line);
	}

	return source_token;
}

static char *sts_get_source_token_from_query(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *source_token = NULL;

	sts_debug(r, "enter");

	apr_table_t *params = apr_table_make(r->pool, 8);
	sts_util_read_form_encoded_params(r->pool, params, r->args);

	sts_debug(r, "parsed: %d bytes into %d elements",
			r->args ? (int )strlen(r->args) : 0, apr_table_elts(params)->nelts);

	const char *query_param_name = sts_get_config_token_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_QUERY_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_SOURCE_TOKEN_QUERY_PARAMNAME_DEFAULT);
	source_token = apr_pstrdup(r->pool,
			apr_table_get(params, query_param_name));

	if (source_token == NULL)
		sts_debug(r, "no source token found in query parameter: %s",
				query_param_name);

	return source_token;
}

static char *sts_get_source_token_from_cookie(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *source_token = NULL;

	sts_debug(r, "enter");

	const char *cookie_name = sts_get_config_token_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_COOKIE_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_SOURCE_TOKEN_COOKIE_NAME_DEFAULT);
	source_token = sts_util_get_cookie(r, cookie_name);
	if (source_token == NULL)
		sts_debug(r, "no source token found in cookie: %s", cookie_name);
	return source_token;
}

static const char *sts_get_source_token(request_rec *r) {

	const char *source_token = NULL;

	int accept_source_token_in = sts_get_accept_source_token_in(r);

	if ((source_token == NULL)
			&& (accept_source_token_in & STS_CONFIG_TOKEN_ENVVAR))
		source_token = sts_get_source_token_from_envvar(r);

	if ((source_token == NULL)
			&& (accept_source_token_in & STS_CONFIG_TOKEN_HEADER))
		source_token = sts_get_source_token_from_header(r);

	if ((source_token == NULL)
			&& (accept_source_token_in & STS_CONFIG_TOKEN_QUERY)) {
		source_token = sts_get_source_token_from_query(r);
	}

	if ((source_token == NULL)
			&& (accept_source_token_in & STS_CONFIG_TOKEN_COOKIE))
		source_token = sts_get_source_token_from_cookie(r);

	if (source_token == NULL) {
		sts_debug(r,
				"no source token found in any of the configured methods: %d",
				accept_source_token_in);
	}

	return source_token;
}

static void sts_set_target_token_in_envvar(request_rec *r, char *target_token) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);

	sts_debug(r, "enter");

	const char *envvar_name = sts_get_config_token_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_ENVVAR_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_TARGET_TOKEN_ENVVAR_NAME_DEFAULT);

	sts_debug(r, "set environment variable: %s=%s", envvar_name, target_token);

	apr_table_set(r->subprocess_env, envvar_name, target_token);
}

static void sts_set_target_token_in_header(request_rec *r, char *target_token) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *header_value = NULL;

	sts_debug(r, "enter");

	const char *header_name = sts_get_config_token_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_TARGET_TOKEN_HEADER_NAME_DEFAULT);
	const char *header_type = sts_get_config_token_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_TYPE,
			STS_TARGET_TOKEN_HEADER_TYPE_DEFAULT);

	header_value =
			(header_type != NULL) ?
					apr_psprintf(r->pool, "%s %s", header_type, target_token) :
					target_token;

	sts_debug(r, "set header to backend: %s: %s", header_name, header_value);

	sts_util_hdr_in_set(r, header_name, header_value);
}

static void sts_set_target_token_in_query(request_rec *r, char *target_token) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	apr_table_t *params = NULL;
	char *encoded = NULL;

	sts_debug(r, "enter");

	const char *query_param_name = sts_get_config_token_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_QUERY_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_TARGET_TOKEN_QUERY_PARAM_NAME_DEFAULT);

	sts_debug(r, "set query parameter to backend: %s=%s", query_param_name,
			target_token);

	params = apr_table_make(r->pool, 1);
	apr_table_set(params, query_param_name, target_token);
	encoded = sts_util_http_form_encoded_data(r, params);

	r->args =
			(r->args != NULL) ?
					apr_psprintf(r->pool, "%s&%s", r->args, encoded) :
					apr_pstrdup(r->pool, encoded);
}

static void sts_set_target_token_in_cookie(request_rec *r, char *target_token) {

	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);

	sts_debug(r, "enter");

	const char *cookie_name = sts_get_config_token_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_COOKIE_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_TARGET_TOKEN_COOKIE_NAME_DEFAULT);

	sts_debug(r, "set cookie to backend: %s=%s", cookie_name, target_token);

	char *value = apr_pstrdup(r->pool,
			apr_table_get(r->headers_in, STS_HEADER_COOKIE));
	value = (value != NULL) ? apr_psprintf(r->pool, "%s; ", value) : "";
	;
	value = apr_psprintf(r->pool, "%s%s=%s", value, cookie_name, target_token);
	apr_table_set(r->headers_in, STS_HEADER_COOKIE, value);
}

static int sts_set_target_token(request_rec *r, char *target_token) {
	int set_target_token_in = sts_get_set_target_token_in(r);

	if (set_target_token_in & STS_CONFIG_TOKEN_ENVVAR)
		sts_set_target_token_in_envvar(r, target_token);

	if (set_target_token_in & STS_CONFIG_TOKEN_HEADER)
		sts_set_target_token_in_header(r, target_token);

	if (set_target_token_in & STS_CONFIG_TOKEN_QUERY) {
		sts_set_target_token_in_query(r, target_token);
	}

	if (set_target_token_in & STS_CONFIG_TOKEN_COOKIE)
		sts_set_target_token_in_cookie(r, target_token);

	return OK;
}

static int sts_handler(request_rec *r) {
	sts_debug(r, "enter");

	if (sts_get_enabled(r) != 1) {
		sts_debug(r, "disabled");
		return DECLINED;
	}

	const char *source_token = sts_get_source_token(r);
	if (source_token == NULL)
		return DECLINED;

	char *target_token = NULL;
	sts_cache_shm_get(r, STS_CACHE_SECTION, source_token, &target_token);

	if (target_token == NULL) {
		sts_debug(r, "cache miss");
		if (sts_util_http_token_exchange(r, source_token, NULL,
				sts_get_ssl_validation(r), &target_token) == FALSE) {
			sts_error(r, "sts_util_http_token_exchange failed");
			return HTTP_UNAUTHORIZED;
		}

		sts_cache_shm_set(r, STS_CACHE_SECTION, source_token, target_token,
				apr_time_now() + apr_time_from_sec(sts_get_cache_expires_in(r)));
	}

	return sts_set_target_token(r, target_token);
}

static int sts_post_read_request(request_rec *r) {
	sts_debug(r, "enter");
	return DECLINED;
}

static int sts_fixup_handler(request_rec *r) {
	sts_debug(r, "enter: \"%s?%s\", ap_is_initial_req(r)=%d",
			r->parsed_uri.path, r->args, ap_is_initial_req(r));
	/*
	 const char *userdata_key = "sts_fixup_handler";
	 void *data = NULL;
	 apr_pool_userdata_get(&data, userdata_key, r->pool);
	 if (data == NULL) {
	 apr_pool_userdata_set((const void *) 1, userdata_key,
	 apr_pool_cleanup_null,r->pool);
	 return sts_handler(r);;
	 }
	 */
	return (ap_is_initial_req(r) != 0) ? sts_handler(r) : OK;
}

const char *ws_trust_soap_call_template =
		"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
		"  <s:Header>"
		"    <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
		"      <wsu:Timestamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"%s\">"
		"        <wsu:Created>%s</wsu:Created>"
		"        <wsu:Expires>%s</wsu:Expires>"
		"      </wsu:Timestamp>"
		"	     <wsse:BinarySecurityToken xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"%s\" ValueType=\"%s\">%s</wsse:BinarySecurityToken>"
		"    </wsse:Security>"
		"    <wsa:To xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">%s</wsa:To>"
		"    <wsa:Action xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">%s</wsa:Action>"
		"  </s:Header>"
		"  <s:Body><wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
		"    <wst:TokenType>%s</wst:TokenType>"
		"    <wst:RequestType>%s</wst:RequestType>"
		"    <wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">"
		"      <wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">"
		"        <wsa:Address>%s</wsa:Address>"
		"      </wsa:EndpointReference>"
		"    </wsp:AppliesTo>"
		"    <wst:KeyType>%s</wst:KeyType>"
		"  </wst:RequestSecurityToken>"
		"  </s:Body>"
		"</s:Envelope>";

#define STR_SIZE 255

int sts_execute_xpath_expression(request_rec *r, const char* xmlStr,
		const xmlChar* xpathExpr, char **rtoken) {
	xmlDocPtr doc;
	xmlXPathContextPtr xpathCtx;
	xmlXPathObjectPtr xpathObj;

	/* Load XML document */
	doc = xmlParseMemory(xmlStr, strlen(xmlStr));
	if (doc == NULL) {
		fprintf(stderr, "Error: unable to parse string \"%s\"\n", xmlStr);
		return (-1);
	}

	/* Create xpath evaluation context */
	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		fprintf(stderr, "Error: unable to create new XPath context\n");
		xmlFreeDoc(doc);
		return (-1);
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "s",
			(const xmlChar *) "http://www.w3.org/2003/05/soap-envelope") != 0) {
		fprintf(stderr, "Error: unable to register NS");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "wst",
			(const xmlChar *) "http://docs.oasis-open.org/ws-sx/ws-trust/200512")
			!= 0) {
		fprintf(stderr, "Error: unable to register NS");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "wsse",
			(const xmlChar *) "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
			!= 0) {
		fprintf(stderr, "Error: unable to register NS");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	/* Evaluate xpath expression */
	xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
	if (xpathObj == NULL) {
		fprintf(stderr, "Error: unable to evaluate xpath expression \"%s\"\n",
				xpathExpr);
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	/* Print results */
	//print_xpath_nodes(r, doc, xpathObj->nodesetval);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
		xmlChar *v = xmlNodeListGetString(doc,
				xpathObj->nodesetval->nodeTab[0]->xmlChildrenNode, 1);
		if (v) {
			int dlen = apr_base64_decode_len((const char *) v);
			*rtoken = apr_palloc(r->pool, dlen);
			apr_base64_decode(*rtoken, (const char *) v);
		}
	}

	/* Cleanup */
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);

	return (0);
}

const char *xpath_expr_template = "/s:Envelope"
		"/s:Body"
		"/wst:RequestSecurityTokenResponseCollection"
		"/wst:RequestSecurityTokenResponse"
		"/wst:RequestedSecurityToken"
		"/wsse:BinarySecurityToken[@ValueType='%s']";

static apr_byte_t sts_exec_wstrust(request_rec *r, const char *token,
		const char *basic_auth, int ssl_validate_server, char **rtoken) {

	char *response = NULL;
	sts_debug(r, "enter");

	const char *id1 = "_0";
	char created[STR_SIZE];
	char expires[STR_SIZE];
	const char *id2 = "Me";

	int enc_len = apr_base64_encode_len(strlen(token));
	char *b64 = apr_palloc(r->pool, enc_len);
	apr_base64_encode(b64, (const char *) token, strlen(token));

	apr_time_t now = apr_time_now();
	apr_time_t then = now + apr_time_from_sec(300);
	apr_size_t size;
	apr_time_exp_t exp;

	apr_time_exp_gmt(&exp, now);
	apr_strftime(created, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	apr_time_exp_gmt(&exp, then);
	apr_strftime(expires, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	char *data = apr_psprintf(r->pool, ws_trust_soap_call_template, id1,
			created, expires, id2, sts_get_wstrust_value_type(r), b64,
			sts_get_wstrust_sts_url(r), STS_CONFIG_DEFAULT_WSTRUST_ACTION,
			sts_get_wstrust_token_type(r),
			STS_CONFIG_DEFAULT_WSTRUST_REQUEST_TYPE,
			sts_get_wstrust_applies_to(r),
			STS_CONFIG_DEFAULT_WSTRUST_KEY_TYPE);

	if (sts_util_http_call(r, sts_get_wstrust_sts_url(r), data,
			"application/soap+xml; charset=utf-8", basic_auth,
			sts_get_wstrust_sts_url(r), ssl_validate_server, &response,
			sts_get_http_timeout(r),
			NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "sts_util_http_call failed!");
		return FALSE;
	}

	xmlInitParser();

	const xmlChar *xpath_expr = (const xmlChar *) apr_psprintf(r->pool,
			xpath_expr_template, sts_get_wstrust_token_type(r));

	if (sts_execute_xpath_expression(r, response, xpath_expr, rtoken) < 0) {
		sts_error(r, "sts_execute_xpath_expression failed!");
		return FALSE;
	}

	sts_warn(r, "returned token=%s", *rtoken);

	xmlCleanupParser();

	return TRUE;
}

#define STS_ROPC_GRANT_TYPE_NAME  "grant_type"
#define STS_ROPC_GRANT_TYPE_VALUE "password"
#define STS_ROPC_CLIENT_ID        "client_id"
#define STS_ROPC_USERNAME         "username"
#define STS_ROPC_PASSWORD         "password"
#define STS_ROPC_ACCESS_TOKEN     "access_token"

static apr_byte_t sts_exec_ropc(request_rec *r, const char *token,
		const char *basic_auth, int ssl_validate_server, char **rtoken) {

	char *response = NULL;

	const char *client_id = sts_get_ropc_client_id(r);
	const char *username = sts_get_ropc_username(r);

	sts_debug(r, "enter");

	apr_table_t *data = apr_table_make(r->pool, 4);
	apr_table_addn(data, STS_ROPC_GRANT_TYPE_NAME, STS_ROPC_GRANT_TYPE_VALUE);
	if (client_id != NULL)
		apr_table_addn(data, STS_ROPC_CLIENT_ID, client_id);
	if (username != NULL)
		apr_table_addn(data, STS_ROPC_USERNAME, username);
	apr_table_addn(data, STS_ROPC_PASSWORD, token);

	if (sts_util_http_post_form(r, sts_get_ropc_token_endpoint(r), data,
			basic_auth, ssl_validate_server, &response, sts_get_http_timeout(r),
			NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "oidc_util_http_post_form failed!");
		return FALSE;
	}

	json_t *result = NULL;
	if (sts_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	apr_byte_t rv = sts_util_json_object_get_string(r->pool, result,
			STS_ROPC_ACCESS_TOKEN, rtoken,
			NULL);
	/*
	 char **token_type = NULL;
	 sts_util_json_object_get_string(r->pool, result, "token_type",
	 token_type,
	 NULL);

	 if (token_type != NULL) {
	 if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
	 oidc_warn(r, "access token type did not validate, dropping it");
	 *access_token = NULL;
	 }
	 }

	 sts_util_json_object_get_int(r->pool, result, OIDC_PROTO_EXPIRES_IN, expires_in,
	 -1);

	 sts_util_json_object_get_string(r->pool, result, OIDC_PROTO_REFRESH_TOKEN,
	 refresh_token,
	 NULL);
	 */

	json_decref(result);

	return rv;
}

#define STS_OAUTH_TX_GRANT_TYPE_NAME          "grant_type"
#define STS_OAUTH_TX_GRANT_TYPE_VALUE         "urn:ietf:params:oauth:grant-type:token-exchange"
#define STS_OAUTH_TX_RESOURCE_NAME            "resource"
#define STS_OAUTH_TX_SUBJECT_TOKEN_NAME       "subject_token"
#define STS_OAUTH_TX_SUBJECT_TOKEN_TYPE_NAME  "subject_token_type"
#define STS_OAUTH_TX_SUBJECT_TOKEN_TYPE_VALUE "urn:ietf:params:oauth:token-type:access_token"
#define STS_OAUTH_TX_ACCESS_TOKEN             "access_token"

static apr_byte_t sts_exec_oauth_token_exchange(request_rec *r,
		const char *token, const char *basic_auth, int ssl_validate_server,
		char **rtoken) {

	char *response = NULL;

	sts_debug(r, "enter");

	const char *resource = sts_get_resource(r);
	if (resource == NULL)
		resource = sts_util_get_current_url(r);

	/*
	 example from IETF draft:

	 grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
	 &resource=https%3A%2F%2Fbackend.example.com%2Fapi%20
	 &subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
	 &subject_token_type=
	 urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
	 */

	apr_table_t *data = apr_table_make(r->pool, 4);
	apr_table_addn(data, STS_OAUTH_TX_GRANT_TYPE_NAME,
			STS_OAUTH_TX_GRANT_TYPE_VALUE);
	if (strcmp(resource, "") != 0)
		apr_table_addn(data, STS_OAUTH_TX_RESOURCE_NAME, resource);
	apr_table_addn(data, STS_OAUTH_TX_SUBJECT_TOKEN_NAME, token);
	apr_table_addn(data, STS_OAUTH_TX_SUBJECT_TOKEN_TYPE_NAME,
			STS_OAUTH_TX_SUBJECT_TOKEN_TYPE_VALUE);

	if (sts_util_http_post_form(r, sts_get_oauth_token_exchange_endpoint(r),
			data, basic_auth, ssl_validate_server, &response,
			sts_get_http_timeout(r),
			NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "oidc_util_http_post_form failed!");
		return FALSE;
	}

	json_t *result = NULL;
	if (sts_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	apr_byte_t rv = sts_util_json_object_get_string(r->pool, result,
			STS_OAUTH_TX_ACCESS_TOKEN, rtoken,
			NULL);

	json_decref(result);

	return rv;
}

apr_byte_t sts_util_http_token_exchange(request_rec *r, const char *token,
		const char *basic_auth, int ssl_validate_server, char **rtoken) {
	int mode = sts_get_mode(r);
	if (mode == STS_CONFIG_MODE_WSTRUST)
		return sts_exec_wstrust(r, token, basic_auth, ssl_validate_server,
				rtoken);
	if (mode == STS_CONFIG_MODE_ROPC)
		return sts_exec_ropc(r, token, basic_auth, ssl_validate_server, rtoken);
	if (mode == STS_CONFIG_MODE_OAUTH_TX)
		return sts_exec_oauth_token_exchange(r, token, basic_auth,
				ssl_validate_server, rtoken);
	sts_error(r, "unknown STS mode %d", mode);
	return FALSE;
}

void *sts_create_server_config(apr_pool_t *pool, server_rec *svr) {
	sts_server_config *c = apr_pcalloc(pool, sizeof(sts_server_config));

	c->mode = STS_CONFIG_POS_INT_UNSET;
	c->ssl_validation = STS_CONFIG_POS_INT_UNSET;
	c->http_timeout = STS_CONFIG_POS_INT_UNSET;

	c->wstrust_sts_url = NULL;
	c->wstrust_applies_to = NULL;
	c->wstrust_token_type = NULL;
	c->wstrust_value_type = NULL;

	c->ropc_token_endpoint = NULL;
	c->ropc_client_id = NULL;
	c->ropc_username = NULL;

	c->oauth_token_exchange_endpoint = NULL;

	c->cache_cfg = NULL;
	//c->cache_shm_size_max = STS_CONFIG_POS_INT_UNSET;
	//c->cache_shm_entry_size_max = STS_CONFIG_POS_INT_UNSET;
	c->cache_shm_size_max = STS_CONFIG_DEFAULT_CACHE_SHM_SIZE;
	c->cache_shm_entry_size_max = STS_CONFIG_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX;
	return c;
}

static void *sts_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	sts_server_config *c = apr_pcalloc(pool, sizeof(sts_server_config));
	sts_server_config *base = BASE;
	sts_server_config *add = ADD;

	c->mode = add->mode != STS_CONFIG_POS_INT_UNSET ? add->mode : base->mode;
	c->ssl_validation =
			add->ssl_validation != STS_CONFIG_POS_INT_UNSET ?
					add->ssl_validation : base->ssl_validation;
	c->http_timeout =
			add->http_timeout != STS_CONFIG_POS_INT_UNSET ?
					add->http_timeout : base->http_timeout;

	c->wstrust_sts_url =
			add->wstrust_sts_url != NULL ?
					add->wstrust_sts_url : base->wstrust_sts_url;
	c->wstrust_applies_to =
			add->wstrust_applies_to != NULL ?
					add->wstrust_applies_to : base->wstrust_applies_to;
	c->wstrust_token_type =
			add->wstrust_token_type != NULL ?
					add->wstrust_token_type : base->wstrust_token_type;
	c->wstrust_value_type =
			add->wstrust_value_type != NULL ?
					add->wstrust_value_type : base->wstrust_value_type;

	c->ropc_token_endpoint =
			add->ropc_token_endpoint != NULL ?
					add->ropc_token_endpoint : base->ropc_token_endpoint;
	c->ropc_client_id =
			add->ropc_client_id != NULL ?
					add->ropc_client_id : base->ropc_client_id;
	c->ropc_username =
			add->ropc_username != NULL ?
					add->ropc_username : base->ropc_username;

	c->oauth_token_exchange_endpoint =
			add->oauth_token_exchange_endpoint != NULL ?
					add->oauth_token_exchange_endpoint :
					base->oauth_token_exchange_endpoint;

	c->cache_cfg = add->cache_cfg != NULL ? add->cache_cfg : base->cache_cfg;
	//c->cache_shm_size_max = add->cache_shm_size_max != STS_CONFIG_POS_INT_UNSET ? add->cache_shm_size_max : base->cache_shm_size_max;
	//c->cache_shm_entry_size_max = add->cache_shm_entry_size_max != STS_CONFIG_POS_INT_UNSET ? add->cache_shm_entry_size_max : base->cache_shm_entry_size_max;
	return c;
}

void *sts_create_dir_config(apr_pool_t *pool, char *path) {
	sts_dir_config *c = apr_pcalloc(pool, sizeof(sts_dir_config));
	c->enabled = STS_CONFIG_POS_INT_UNSET;
	c->cache_expires_in = STS_CONFIG_POS_INT_UNSET;
	c->accept_source_token_in = STS_CONFIG_POS_INT_UNSET;
	c->accept_source_token_in_options = NULL;
	c->set_target_token_in = STS_CONFIG_POS_INT_UNSET;
	c->set_target_token_in_options = NULL;
	c->resource = NULL;
	return c;
}

static void *sts_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	sts_dir_config *c = apr_pcalloc(pool, sizeof(sts_dir_config));
	sts_dir_config *base = BASE;
	sts_dir_config *add = ADD;
	c->enabled =
			add->enabled != STS_CONFIG_POS_INT_UNSET ?
					add->enabled : base->enabled;
	c->cache_expires_in =
			add->cache_expires_in != STS_CONFIG_POS_INT_UNSET ?
					add->cache_expires_in : base->cache_expires_in;
	c->accept_source_token_in =
			add->accept_source_token_in != STS_CONFIG_POS_INT_UNSET ?
					add->accept_source_token_in : base->accept_source_token_in;
	c->accept_source_token_in_options =
			add->accept_source_token_in_options != NULL ?
					add->accept_source_token_in_options :
					base->accept_source_token_in_options;

	c->resource = add->resource != NULL ? add->resource : base->resource;
	return c;
}

static void sts_register_hooks(apr_pool_t *p) {
	ap_hook_post_config(sts_post_config_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(sts_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(sts_post_read_request, NULL, NULL, APR_HOOK_LAST);
	static const char * const aszPre[] = { "mod_auth_openidc.c", NULL };
	ap_hook_fixups(sts_fixup_handler, aszPre, NULL, APR_HOOK_MIDDLE);
}

static const command_rec sts_cmds[] = {

		AP_INIT_FLAG(
				"STSEnabled",
				ap_set_flag_slot,
				(void*)APR_OFFSETOF(sts_dir_config, enabled),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Enable or disable mod_sts."),

		AP_INIT_TAKE1(
				"STSMode",
				sts_set_mode,
				(void*)APR_OFFSETOF(sts_server_config, mode),
				RSRC_CONF,
				"Set STS mode to \"" STS_CONFIG_MODE_WSTRUST_STR "\", \"" STS_CONFIG_MODE_ROPC_STR "\" or \"" STS_CONFIG_MODE_OAUTH_TX_STR "\"."),
		AP_INIT_FLAG(
				"STSSSLValidateServer",
				sts_set_flag_slot,
				(void*)APR_OFFSETOF(sts_server_config, ssl_validation),
				RSRC_CONF,
				"Enable or disable SSL server certificate validation for calls to the STS."),
		AP_INIT_TAKE1(
				"STSHTTPTimeOut",
				sts_set_int_slot,
				(void*)APR_OFFSETOF(sts_server_config, http_timeout),
				RSRC_CONF,
				"Timeout for calls to the STS."),

		AP_INIT_TAKE1(
				"STSResource",
				ap_set_string_slot,
				(void*)APR_OFFSETOF(sts_dir_config, resource),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the STS resource value."),

		AP_INIT_TAKE1(
				"STSWSTrustUrl",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_sts_url),
				RSRC_CONF,
				"Set the WS-Trust STS endpoint."),
		AP_INIT_TAKE1(
				"STSWSTrustAppliesTo",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_applies_to),
				RSRC_CONF,
				"Set the WS-Trust AppliesTo value."),
		AP_INIT_TAKE1(
				"STSWSTrustTokenType",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_token_type),
				RSRC_CONF,
				"Set the WS-Trust Token Type."),
		AP_INIT_TAKE1(
				"STSWSTrustValueType",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_value_type),
				RSRC_CONF,
				"Set the WS-Trust Value Type."),

		AP_INIT_TAKE1(
				"STSROPCTokenEndpoint",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_token_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 ROPC Token Endpoint."),
		AP_INIT_TAKE1(
				"STSROPCClientID",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_client_id),
				RSRC_CONF,
				"Set the Client ID for the OAuth 2.0 ROPC token request."),
		AP_INIT_TAKE1(
				"STSROPCUsername",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_username),
				RSRC_CONF,
				"Set the username to be used in the OAuth 2.0 ROPC token request; if left empty the client_id will be passed in the username parameter."),

		AP_INIT_TAKE1(
				"STSOAuthTokenExchangeEndpoint",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, oauth_token_exchange_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 Token Exchange Endpoint."),

		AP_INIT_TAKE1(
				"STSCacheExpiresIn",
				ap_set_int_slot,
				(void*)APR_OFFSETOF(sts_dir_config, cache_expires_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the cache expiry for access tokens in seconds."),

		AP_INIT_ITERATE(
				"STSAcceptSourceTokenIn",
				sts_set_accept_source_token_in,
				(void*)APR_OFFSETOF(sts_dir_config, accept_source_token_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Configure how the source token may be presented."),

		AP_INIT_ITERATE(
				"STSSetTargetTokenIn",
				sts_set_set_target_token_in,
				(void*)APR_OFFSETOF(sts_dir_config, set_target_token_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the way in which the target token is passed to the backend."),

		{ NULL }

};

module AP_MODULE_DECLARE_DATA sts_module = {
		STANDARD20_MODULE_STUFF,
		sts_create_dir_config,
		sts_merge_dir_config,
		sts_create_server_config,
		sts_merge_server_config,
		sts_cmds,
		sts_register_hooks
};

