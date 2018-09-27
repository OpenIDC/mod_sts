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

// TODO: add client_secret_jwt and private_key_jwt to the auth options of the OAuth-based STS methods
// TODO: check for a sane configuration at startup (and leave current localhost defaults to null)
// TODO: is the fixup handler the right place for the sts_handler
//       or should we only handle source/target envvar stuff there?
// TODO: strip the source token from the propagated request? (optionally?)
//       FWIW: the authorization header will be overwritten
#include "mod_sts.h"

module AP_MODULE_DECLARE_DATA sts_module;

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
static const int STS_CONFIG_TOKEN_ENVVAR = 1;
#define STS_CONFIG_TOKEN_HEADER_STR                "header"
static const int STS_CONFIG_TOKEN_HEADER = 2;
#define STS_CONFIG_TOKEN_QUERY_STR                 "query"
static const int STS_CONFIG_TOKEN_QUERY = 4;
#define STS_CONFIG_TOKEN_COOKIE_STR                "cookie"
static const int STS_CONFIG_TOKEN_COOKIE = 8;

#define STS_DEFAULT_ACCEPT_SOURCE_TOKEN_IN         (STS_CONFIG_TOKEN_ENVVAR | STS_CONFIG_TOKEN_HEADER)
#define STS_DEFAULT_SET_TARGET_TOKEN_IN            (STS_CONFIG_TOKEN_ENVVAR | STS_CONFIG_TOKEN_COOKIE)

#define STS_HEADER_AUTHORIZATION_BEARER            "Bearer"

#define STS_CONFIG_OPTION_SEPARATOR                ":"

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

const int STS_ENDPOINT_AUTH_NONE = 0;
const int STS_ENDPOINT_AUTH_BASIC = 1;
const int STS_ENDPOINT_AUTH_CLIENT_CERT = 2;
const int STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC = 3;
const int STS_ENDPOINT_AUTH_CLIENT_SECRET_POST = 4;
const int STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT = 5;
const int STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT = 6;

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

static void sts_set_config_method_options(cmd_parms *cmd,
		apr_hash_t **method_options, const char *type, char *options) {
	if (options != NULL) {
		apr_table_t *params = apr_table_make(cmd->pool, 8);
		sts_util_read_form_encoded_params(cmd->pool, params, options);

		sts_sdebug(cmd->server, "parsed: %d bytes into %d elements",
				(int )strlen(options), apr_table_elts(params)->nelts);

		if (*method_options == NULL)
			*method_options = apr_hash_make(cmd->pool);
		apr_hash_set(*method_options, type,
				APR_HASH_KEY_STRING, params);
	}
}

static apr_hash_t *sts_get_allowed_token_options(apr_pool_t *pool,
		char *allowed[]) {
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

static apr_hash_t *sts_get_allowed_endpoint_auth_methods(apr_pool_t *pool,
		char *allowed[]) {
	apr_hash_t *methods = apr_hash_make(pool);
	int i = 0;
	while (allowed[i] != NULL) {
		if (apr_strnatcmp(STS_ENDPOINT_AUTH_BASIC_STR, allowed[i]) == 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_BASIC_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_BASIC);
		} else if (apr_strnatcmp(STS_ENDPOINT_AUTH_CLIENT_CERT_STR, allowed[i])
				== 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_CLIENT_CERT);
		} else if (apr_strnatcmp(STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
				allowed[i]) == 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC);
		} else if (apr_strnatcmp(STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
				allowed[i]) == 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_CLIENT_SECRET_POST);
		} else if (apr_strnatcmp(STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
				allowed[i]) == 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT);
		} else if (apr_strnatcmp(STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
				allowed[i]) == 0) {
			apr_hash_set(methods, STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
					APR_HASH_KEY_STRING, &STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT);
		}
		i++;
	}
	return methods;
}

typedef apr_hash_t *(*sts_allowed_methods_function_t)(apr_pool_t *pool,
		char *allowed[]);

static const char *sts_set_method_options(cmd_parms *cmd, const char *arg,
		char *allowed[], sts_allowed_methods_function_t sts_get_allowed_methods,
		int *rmethod, apr_hash_t **rmethod_options) {
	char *rv = NULL;
	int i = 0;
	apr_hash_t *allowed_methods = sts_get_allowed_methods(cmd->pool, allowed);

	const char *method = apr_pstrdup(cmd->pool, arg);
	char *option = strstr(method, STS_CONFIG_OPTION_SEPARATOR);
	if (option != NULL) {
		*option = '\0';
		option++;
	}

	int *vp = apr_hash_get(allowed_methods, method, APR_HASH_KEY_STRING);
	if (vp != NULL) {
		if (*rmethod == STS_CONFIG_POS_INT_UNSET)
			(*rmethod) = (*vp);
		else
			(*rmethod) |= (*vp);
		sts_set_config_method_options(cmd, rmethod_options, method, option);
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
	return sts_set_method_options(cmd, arg, options,
			sts_get_allowed_token_options, &dir_cfg->accept_source_token_in,
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
	return sts_set_method_options(cmd, arg, options,
			sts_get_allowed_token_options, &dir_cfg->set_target_token_in,
			&dir_cfg->set_target_token_in_options);
}

static const char *sts_set_wstrust_endpoint_auth(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	static char *methods[] = {
			STS_ENDPOINT_AUTH_BASIC_STR,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			NULL };
	return sts_set_method_options(cmd, arg, methods,
			sts_get_allowed_endpoint_auth_methods, &cfg->wstrust_endpoint_auth,
			&cfg->wstrust_endpoint_auth_options);
}

static const char *sts_set_ropc_endpoint_auth(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	static char *methods[] = {
			STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
			STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			NULL };
	return sts_set_method_options(cmd, arg, methods,
			sts_get_allowed_endpoint_auth_methods, &cfg->ropc_endpoint_auth,
			&cfg->ropc_endpoint_auth_options);
}

static const char *sts_set_oauth_tx_endpoint_auth(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	static char *methods[] = {
			STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
			STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			NULL };
	return sts_set_method_options(cmd, arg, methods,
			sts_get_allowed_endpoint_auth_methods, &cfg->oauth_tx_endpoint_auth,
			&cfg->oauth_tx_endpoint_auth_options);
}

int sts_get_http_timeout(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->http_timeout == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_HTTP_TIMEOUT;
	return cfg->http_timeout;
}

static int sts_get_enabled(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->enabled == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_ENABLED;
	return dir_cfg->enabled;
}

int sts_get_ssl_validation(request_rec *r) {
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

const char * sts_get_resource(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	return dir_cfg->resource;
}

const char *sts_get_config_method_option(request_rec *r,
		apr_hash_t *config_method_options, const char *type, const char *key,
		char *default_value) {
	const char *rv = NULL;
	if (config_method_options != NULL) {
		apr_table_t *options = (apr_table_t *) apr_hash_get(
				config_method_options, type,
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

	const char *envvar_name = sts_get_config_method_option(r,
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

	const char *name = sts_get_config_method_option(r,
			dir_cfg->accept_source_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_SOURCE_TOKEN_HEADER_NAME_DEFAULT);
	const char *type = sts_get_config_method_option(r,
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

	const char *query_param_name = sts_get_config_method_option(r,
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

	const char *cookie_name = sts_get_config_method_option(r,
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

	const char *envvar_name = sts_get_config_method_option(r,
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

	const char *header_name = sts_get_config_method_option(r,
			dir_cfg->set_target_token_in_options,
			STS_CONFIG_TOKEN_HEADER_STR,
			STS_CONFIG_TOKEN_OPTION_NAME,
			STS_TARGET_TOKEN_HEADER_NAME_DEFAULT);
	const char *header_type = sts_get_config_method_option(r,
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

	const char *query_param_name = sts_get_config_method_option(r,
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

	const char *cookie_name = sts_get_config_method_option(r,
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
		if (sts_util_token_exchange(r, source_token, &target_token) == FALSE) {
			sts_error(r, "sts_util_token_exchange failed");
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

apr_byte_t sts_get_endpoint_auth_cert_key(request_rec *r, apr_hash_t *options,
		const char **client_cert, const char **client_key) {
	*client_cert = sts_get_config_method_option(r, options,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			STS_ENDPOINT_AUTH_OPTION_CERT,
			NULL);
	*client_key = sts_get_config_method_option(r, options,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			STS_ENDPOINT_AUTH_OPTION_KEY,
			NULL);
	if (*client_cert == NULL) {
		sts_error(r,
				"when using \"" STS_ENDPOINT_AUTH_CLIENT_CERT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_CERT "\" option must be set on the configuration directive");
		return FALSE;
	}
	if (*client_key == NULL) {
		sts_error(r,
				"when using \"" STS_ENDPOINT_AUTH_CLIENT_CERT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_KEY "\" option must be set on the configuration directive");
		return FALSE;
	}
	return TRUE;
}

apr_byte_t sts_get_oauth_endpoint_auth(request_rec *r, int auth,
		apr_hash_t *auth_options, apr_table_t *params, const char *client_id,
		char **basic_auth, const char **client_cert, const char **client_key) {
	if (auth != STS_ENDPOINT_AUTH_NONE) {
		if (auth == STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC) {
			if (client_id == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR "\" the client_id must be set the configuration.");
				return FALSE;
			}
			const char *secret = sts_get_config_method_option(r, auth_options,
					STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
					STS_ENDPOINT_AUTH_OPTION_SECRET,
					NULL);
			if (secret == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_SECRET "\" option must be set on the configuration directive");
				return FALSE;
			}
			*basic_auth = apr_psprintf(r->pool, "%s:%s", client_id, secret);
		} else if (auth == STS_ENDPOINT_AUTH_CLIENT_SECRET_POST) {
			if (client_id == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR "\" the client_id must be set the configuration.");
				return FALSE;
			}
			const char *client_secret = sts_get_config_method_option(r,
					auth_options,
					STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
					STS_ENDPOINT_AUTH_OPTION_SECRET,
					NULL);
			if (client_secret == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_SECRET "\" option must be set on the configuration directive");
				return FALSE;
			}
			apr_table_set(params, STS_OAUTH_CLIENT_ID, client_id);
			apr_table_set(params, STS_OAUTH_CLIENT_SECRET, client_secret);
		} else if (auth == STS_ENDPOINT_AUTH_CLIENT_CERT) {
			if (sts_get_endpoint_auth_cert_key(r, auth_options, client_cert,
					client_key) == FALSE)
				return FALSE;
		}
	}
	return TRUE;
}

apr_byte_t sts_util_token_exchange(request_rec *r, const char *token,
		char **rtoken) {
	int mode = sts_get_mode(r);
	if (mode == STS_CONFIG_MODE_WSTRUST)
		return sts_exec_wstrust(r, token, rtoken);
	if (mode == STS_CONFIG_MODE_ROPC)
		return sts_exec_ropc(r, token, rtoken);
	if (mode == STS_CONFIG_MODE_OAUTH_TX)
		return sts_exec_otx(r, token, rtoken);
	sts_error(r, "unknown STS mode %d", mode);
	return FALSE;
}

void *sts_create_server_config(apr_pool_t *pool, server_rec *svr) {
	sts_server_config *c = apr_pcalloc(pool, sizeof(sts_server_config));

	c->mode = STS_CONFIG_POS_INT_UNSET;
	c->ssl_validation = STS_CONFIG_POS_INT_UNSET;
	c->http_timeout = STS_CONFIG_POS_INT_UNSET;

	c->wstrust_endpoint = NULL;
	c->wstrust_endpoint_auth = STS_CONFIG_POS_INT_UNSET;
	c->wstrust_endpoint_auth_options = NULL;

	c->wstrust_applies_to = NULL;
	c->wstrust_token_type = NULL;
	c->wstrust_value_type = NULL;

	c->ropc_endpoint = NULL;
	c->ropc_endpoint_auth = STS_CONFIG_POS_INT_UNSET;
	c->ropc_endpoint_auth_options = NULL;
	c->ropc_client_id = NULL;
	c->ropc_username = NULL;

	c->oauth_tx_endpoint = NULL;
	c->oauth_tx_endpoint_auth = STS_CONFIG_POS_INT_UNSET;
	c->oauth_tx_endpoint_auth_options = NULL;
	c->oauth_tx_client_id = NULL;

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

	c->wstrust_endpoint =
			add->wstrust_endpoint != NULL ?
					add->wstrust_endpoint : base->wstrust_endpoint;
	c->wstrust_endpoint_auth =
			add->wstrust_endpoint_auth != STS_CONFIG_POS_INT_UNSET ?
					add->wstrust_endpoint_auth : base->wstrust_endpoint_auth;
	c->wstrust_endpoint_auth_options =
			add->wstrust_endpoint_auth_options != NULL ?
					add->wstrust_endpoint_auth_options :
					base->wstrust_endpoint_auth_options;
	c->wstrust_applies_to =
			add->wstrust_applies_to != NULL ?
					add->wstrust_applies_to : base->wstrust_applies_to;
	c->wstrust_token_type =
			add->wstrust_token_type != NULL ?
					add->wstrust_token_type : base->wstrust_token_type;
	c->wstrust_value_type =
			add->wstrust_value_type != NULL ?
					add->wstrust_value_type : base->wstrust_value_type;

	c->ropc_endpoint =
			add->ropc_endpoint != NULL ?
					add->ropc_endpoint : base->ropc_endpoint;
	c->ropc_endpoint_auth =
			add->ropc_endpoint_auth != STS_CONFIG_POS_INT_UNSET ?
					add->ropc_endpoint_auth : base->ropc_endpoint_auth;
	c->ropc_endpoint_auth_options =
			add->ropc_endpoint_auth_options != NULL ?
					add->ropc_endpoint_auth_options :
					base->ropc_endpoint_auth_options;
	c->ropc_client_id =
			add->ropc_client_id != NULL ?
					add->ropc_client_id : base->ropc_client_id;
	c->ropc_username =
			add->ropc_username != NULL ?
					add->ropc_username : base->ropc_username;

	c->oauth_tx_endpoint =
			add->oauth_tx_endpoint != NULL ?
					add->oauth_tx_endpoint : base->oauth_tx_endpoint;
	c->oauth_tx_endpoint_auth =
			add->oauth_tx_endpoint_auth != STS_CONFIG_POS_INT_UNSET ?
					add->oauth_tx_endpoint_auth : base->oauth_tx_endpoint_auth;
	c->oauth_tx_endpoint_auth_options =
			add->oauth_tx_endpoint_auth_options != NULL ?
					add->oauth_tx_endpoint_auth_options :
					base->oauth_tx_endpoint_auth_options;
	c->oauth_tx_client_id =
			add->oauth_tx_client_id != NULL ?
					add->oauth_tx_client_id : base->oauth_tx_client_id;

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
				"STSWSTrustEndpoint",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_endpoint),
				RSRC_CONF,
				"Set the WS-Trust STS endpoint."),
		AP_INIT_TAKE1(
				"STSWSTrustEndpointAuth",
				sts_set_wstrust_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the WS-Trust Endpoint."),
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
				"STSROPCEndpoint",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 ROPC Token Endpoint."),
		AP_INIT_TAKE1(
				"STSROPCEndpointAuth",
				sts_set_ropc_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, ropc_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the ROPC Endpoint."),
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
				(void*)APR_OFFSETOF(sts_server_config, oauth_tx_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 Token Exchange Endpoint."),
		AP_INIT_TAKE1(
				"STSOAuthTokenExchangeEndpointAuth",
				sts_set_oauth_tx_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, oauth_tx_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the OAuth 2.0 Token Exchange Endpoint."),
		AP_INIT_TAKE1(
				"STSOAuthTokenExchangeClientID",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, oauth_tx_client_id),
				RSRC_CONF,
				"Set the Client ID for the OAuth 2.0 Token Exchange request."),

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

