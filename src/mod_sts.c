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

// TOOD: ws-trust source tokens can only be presented as BinarySecurityToken's; should we support native SAML 2.0 etc.?
// TODO: support consuming a source token from a POST parameter (difficult not to consume the POST data...)?
#include "mod_sts.h"

#include <cjose/cjose.h>

module AP_MODULE_DECLARE_DATA sts_module;

#define STS_CONFIG_DEFAULT_CACHE_SHM_SIZE          2048
#define STS_CONFIG_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 4096 + 512 + 17

#define STS_CONFIG_DEFAULT_CACHE_EXPIRES_IN        300

#define STS_CONFIG_MODE_WSTRUST_STR                "wstrust"
#define STS_CONFIG_MODE_WSTRUST                    0
#define STS_CONFIG_MODE_ROPC_STR                   "ropc"
#define STS_CONFIG_MODE_ROPC                       1
#define STS_CONFIG_MODE_OTX_STR                    "otx"
#define STS_CONFIG_MODE_OTX                        2

#define STS_CONFIG_DEFAULT_STS_MODE                STS_CONFIG_MODE_WSTRUST

#define STS_CACHE_SECTION                          "sts"

#define STS_CONFIG_DEFAULT_STRIP_SOURCE_TOKEN      1
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

static int sts_config_merged_vhost_configs_exist(server_rec *s) {
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

int sts_config_check_vhost_config(apr_pool_t *pool, server_rec *s) {
	sts_server_config *cfg = ap_get_module_config(s->module_config,
			&sts_module);
	int rc = OK;
	switch (cfg->mode) {
	case STS_CONFIG_MODE_WSTRUST:
		rc = sts_wstrust_config_check_vhost(pool, s, cfg);
		break;
	case STS_CONFIG_MODE_ROPC:
		rc = sts_ropc_config_check_vhost(pool, s, cfg);
		break;
	case STS_CONFIG_MODE_OTX:
		rc = sts_otx_config_check_vhost(pool, s, cfg);
		break;
	default:
		sts_serror(s, "STS mode is set to unsupported value: %d", cfg->mode);
		rc = HTTP_INTERNAL_SERVER_ERROR;
		break;

	}
	return rc;
}

static int sts_config_check_merged_vhost_configs(apr_pool_t *pool,
		server_rec *s) {
	sts_server_config *cfg = NULL;
	int rc = OK;
	while (s != NULL) {
		cfg = ap_get_module_config(s->module_config, &sts_module);
		if (cfg->merged) {
			rc = sts_config_check_vhost_config(pool, s);
			if (rc != OK) {
				break;
			}
		}
		s = s->next;
	}
	return rc;
}

static int sts_post_config_handler(apr_pool_t *pool, apr_pool_t *p1,
		apr_pool_t *p2, server_rec *s) {

	const char *userdata_key = "sts_post_config";
	void *data = NULL;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
				apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	sts_sinfo(s, "%s - init", NAMEVERSION);
	apr_pool_cleanup_register(pool, s, sts_cleanup_handler,
			apr_pool_cleanup_null);

	server_rec *sp = s;
	while (sp != NULL) {
		if (sts_cache_shm_post_config(sp) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
		sp = sp->next;
	}

	/*
	 * Apache has a base vhost that true vhosts derive from.
	 * There are two startup scenarios:
	 *
	 * 1. Only the base vhost contains OIDC settings.
	 *    No server configs have been merged.
	 *    Only the base vhost needs to be checked.
	 *
	 * 2. The base vhost contains zero or more OIDC settings.
	 *    One or more vhosts override these.
	 *    These vhosts have a merged config.
	 *    All merged configs need to be checked.
	 */
	if (!sts_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
		return sts_config_check_vhost_config(pool, s);
	}
	return sts_config_check_merged_vhost_configs(pool, s);
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
	if (strcmp(arg, STS_CONFIG_MODE_OTX_STR) == 0) {
		cfg->mode = STS_CONFIG_MODE_OTX;
		return NULL;
	}

	return "Invalid value: must be \"" STS_CONFIG_MODE_WSTRUST_STR "\", \"" STS_CONFIG_MODE_ROPC_STR "\" or \"" STS_CONFIG_MODE_OTX_STR "\"";
}

static void sts_set_config_method_options(cmd_parms *cmd,
		apr_hash_t **method_options, const char *type, char *options) {
	if (options != NULL) {
		apr_table_t *params = apr_table_make(cmd->pool, 8);
		sts_util_read_form_encoded_params(cmd->pool, params, options);
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
			STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
			STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			NULL };
	return sts_set_method_options(cmd, arg, methods,
			sts_get_allowed_endpoint_auth_methods, &cfg->ropc_endpoint_auth,
			&cfg->ropc_endpoint_auth_options);
}

static const char *sts_set_otx_endpoint_auth(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			cmd->server->module_config, &sts_module);
	static char *methods[] = {
			STS_ENDPOINT_AUTH_CLIENT_SECRET_BASIC_STR,
			STS_ENDPOINT_AUTH_CLIENT_SECRET_POST_STR,
			STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
			STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			NULL };
	return sts_set_method_options(cmd, arg, methods,
			sts_get_allowed_endpoint_auth_methods, &cfg->otx_endpoint_auth,
			&cfg->otx_endpoint_auth_options);
}

static const char *sts_set_request_parameter(cmd_parms *cmd, void *m,
		const char *arg1, const char *arg2) {
	sts_dir_config *dir_cfg = (sts_dir_config *) m;
	if (dir_cfg->request_parameters == NULL)
		dir_cfg->request_parameters = apr_table_make(cmd->pool, 2);
	apr_table_add(dir_cfg->request_parameters, arg1, arg2);
	return NULL;
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

static int sts_get_strip_source_token(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->strip_source_token == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_STRIP_SOURCE_TOKEN;
	return dir_cfg->strip_source_token;
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

const char *sts_get_config_method_option(request_rec *r,
		apr_hash_t *config_method_options, const char *type, const char *key,
		const char *default_value) {
	const char *rv = NULL;
	if (config_method_options != NULL) {
		apr_table_t *options = (apr_table_t *) apr_hash_get(
				config_method_options, type,
				APR_HASH_KEY_STRING);
		if (options != NULL)
			rv = apr_table_get(options, key);
	}
	if (rv == NULL)
		rv = apr_pstrdup(r->pool, default_value);
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
	} else if (sts_get_strip_source_token(r) != 0) {
		apr_table_unset(r->subprocess_env, envvar_name);
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

	const char *auth_line = sts_util_hdr_in_get(r, name);
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

	if ((source_token != NULL) && (sts_get_strip_source_token(r) != 0))
		sts_util_hdr_in_set(r, name, NULL);

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

	if (source_token == NULL) {
		sts_debug(r, "no source token found in query parameter: %s",
				query_param_name);
	} else if (sts_get_strip_source_token(r) != 0) {
		sts_debug(r, "stripping query param %s from outgoing request",
				query_param_name);
		apr_table_unset(params, query_param_name);
		r->args = sts_util_http_form_encoded_data(r, params);
	}

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
	source_token = sts_util_get_cookie(r, cookie_name,
			sts_get_strip_source_token(r));
	if (source_token == NULL)
		sts_debug(r, "no source token found in cookie: %s", cookie_name);
	return source_token;
}

static char *sts_get_source_token(request_rec *r) {

	char *source_token = NULL;

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

	const char *value = sts_util_hdr_in_get(r, STS_HEADER_COOKIE);
	value = (value != NULL) ? apr_psprintf(r->pool, "%s; ", value) : "";

	value = apr_psprintf(r->pool, "%s%s=%s", value, cookie_name, target_token);
	sts_util_hdr_in_set(r, STS_HEADER_COOKIE, value);

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

static int sts_handler(request_rec *r, char **source_token) {
	char *target_token = NULL, *cache_key = NULL;
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);

	sts_debug(r, "enter");

	if (sts_get_enabled(r) != 1) {
		sts_debug(r, "disabled");
		return DECLINED;
	}

	*source_token = sts_get_source_token(r);
	if (*source_token == NULL)
		return DECLINED;

	cache_key = apr_psprintf(r->pool, "%s:%s", dir_cfg->path, *source_token);
	sts_cache_shm_get(r, STS_CACHE_SECTION, cache_key, &target_token);

	if (target_token == NULL) {
		sts_debug(r, "cache miss (%s)", cache_key);
		if (sts_util_token_exchange(r, *source_token, &target_token) == FALSE) {
			sts_error(r, "sts_util_token_exchange failed");
			return HTTP_UNAUTHORIZED;
		}

		sts_cache_shm_set(r, STS_CACHE_SECTION, cache_key, target_token,
				apr_time_now() + apr_time_from_sec(sts_get_cache_expires_in(r)));
	} else {
		sts_debug(r, "cache hit (%s)", cache_key);
	}

	return sts_set_target_token(r, target_token);
}

static const char *userdata_key = "sts_fixup_handler";

static int sts_post_read_request(request_rec *r) {
	sts_debug(r, "enter: \"%s?%s\", ap_is_initial_req(r)=%d",
			r->parsed_uri.path, r->args, ap_is_initial_req(r));

	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	char *source_token = NULL;
	int rc = DECLINED;

	if (ap_is_initial_req(r) == 0)
		return DECLINED;

	rc = sts_handler(r, &source_token);

	// if the source token comes from an env var, that may not have been set until
	// the fixup handler runs, so we'll indicated that we want to run at fixup time
	if ((rc == DECLINED) && (source_token == NULL)
			&& (dir_cfg->accept_source_token_in & STS_CONFIG_TOKEN_ENVVAR)) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
				apr_pool_cleanup_null, r->pool);
	}

	sts_debug(r, "leave: %d", rc);
	return rc;
}

static int sts_fixup_handler(request_rec *r) {
	sts_debug(r, "enter: \"%s?%s\", ap_is_initial_req(r)=%d",
			r->parsed_uri.path, r->args, ap_is_initial_req(r));

	if (ap_is_initial_req(r) == 0)
		return DECLINED;

	char *source_token = NULL;
	int rc = DECLINED;
	void *data = NULL;
	apr_pool_userdata_get(&data, userdata_key, r->pool);
	// TBD: do we need to only handle env var stuff; right now it also looks for tokens elsewhere
	// TBD: always set target env var token in the fixup handler to be "more authoritative"?
	if (data != NULL)
		rc = sts_handler(r, &source_token);

	sts_debug(r, "leave: %d", rc);
	return rc;
}

apr_byte_t sts_get_endpoint_auth_cert_key(request_rec *r, apr_hash_t *options,
		const char **client_cert, const char **client_key) {
	const char *cert = sts_get_config_method_option(r, options,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			STS_ENDPOINT_AUTH_OPTION_CERT,
			NULL);
	const char *key = sts_get_config_method_option(r, options,
			STS_ENDPOINT_AUTH_CLIENT_CERT_STR,
			STS_ENDPOINT_AUTH_OPTION_KEY,
			NULL);
	if (cert == NULL) {
		sts_error(r,
				"when using \"" STS_ENDPOINT_AUTH_CLIENT_CERT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_CERT "\" option must be set on the configuration directive");
		return FALSE;
	}
	if (key == NULL) {
		sts_error(r,
				"when using \"" STS_ENDPOINT_AUTH_CLIENT_CERT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_KEY "\" option must be set on the configuration directive");
		return FALSE;
	}
	*client_cert = sts_util_get_full_path(r->pool, cert);
	*client_key = sts_util_get_full_path(r->pool, key);
	return TRUE;
}

#define STS_JOSE_HDR_TYP                           "typ"
#define STS_JOSE_HDR_TYP_JWT                       "JWT"
#define STS_OAUTH_CLAIM_ISS                        "iss"
#define STS_OAUTH_CLAIM_SUB                        "sub"
#define STS_OAUTH_CLAIM_JTI                        "jti"
#define STS_OAUTH_CLAIM_EXP                        "exp"
#define STS_OAUTH_CLAIM_AUD                        "aud"
#define STS_OAUTH_CLAIM_IAT                        "iat"
#define STS_OAUTH_CLIENT_ASSERTION                 "client_assertion"
#define STS_OAUTH_CLIENT_ASSERTION_TYPE            "client_assertion_type"
#define STS_OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#define sts_cjose_e2s(pool, err) apr_psprintf(pool, "%s [file: %s, function: %s, line: %ld]\n", err.message, err.file, err.function, err.line)

static apr_byte_t sts_add_signed_jwt_and_release_jwk(request_rec *r,
		cjose_jwk_t *jwk, const char *alg, const char *client_id,
		const char *audience, apr_table_t *params) {

	sts_debug(r, "enter");

	apr_byte_t rc = FALSE;
	char *payload = NULL;
	json_t *json = NULL;
	cjose_header_t *hdr = NULL;
	cjose_jws_t *jws = NULL;
	const char *jwt = NULL;
	cjose_err err;

	json = json_object();
	json_object_set_new(json, STS_OAUTH_CLAIM_JTI,
			json_string(sts_generate_random_string(r->pool, 16)));
	json_object_set_new(json, STS_OAUTH_CLAIM_ISS, json_string(client_id));
	json_object_set_new(json, STS_OAUTH_CLAIM_SUB, json_string(client_id));
	json_object_set_new(json, STS_OAUTH_CLAIM_AUD, json_string(audience));
	json_object_set_new(json, STS_OAUTH_CLAIM_EXP,
			json_integer(apr_time_sec(apr_time_now()) + 60));
	json_object_set_new(json, STS_OAUTH_CLAIM_IAT,
			json_integer(apr_time_sec(apr_time_now())));
	payload = json_dumps(json,
			JSON_PRESERVE_ORDER | JSON_COMPACT);

	hdr = cjose_header_new(&err);
	if (hdr == NULL) {
		sts_error(r, "cjose_header_new failed: %s",
				sts_cjose_e2s(r->pool, err));
		goto out;
	}
	if (cjose_header_set(hdr, CJOSE_HDR_ALG, alg, &err) == FALSE) {
		sts_error(r, "cjose_header_set %s:%s failed: %s", CJOSE_HDR_ALG, alg,
				sts_cjose_e2s(r->pool, err));
		goto out;
	}
	if (cjose_header_set(hdr, STS_JOSE_HDR_TYP, STS_JOSE_HDR_TYP_JWT,
			&err) == FALSE) {
		sts_error(r, "cjose_header_set %s:%s failed: %s", STS_JOSE_HDR_TYP,
				STS_JOSE_HDR_TYP_JWT, sts_cjose_e2s(r->pool, err));
		goto out;
	}

	jws = cjose_jws_sign(jwk, hdr, (const uint8_t *) payload, strlen(payload),
			&err);
	if (jws == NULL) {
		sts_error(r, "cjose_jws_sign failed: %s", sts_cjose_e2s(r->pool, err));
		goto out;
	}

	if (cjose_jws_export(jws, &jwt, &err) == FALSE) {
		sts_error(r, "cjose_jws_export failed: %s",
				sts_cjose_e2s(r->pool, err));
		goto out;
	}

	apr_table_setn(params, STS_OAUTH_CLIENT_ASSERTION_TYPE,
			STS_OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER);
	apr_table_set(params, STS_OAUTH_CLIENT_ASSERTION, jwt);

	rc = TRUE;

out:

	if (json)
		json_decref(json);
	if (payload)
		free(payload);
	if (hdr)
		cjose_header_release(hdr);
	if (jws)
		cjose_jws_release(jws);
	if (jwk)
		cjose_jwk_release(jwk);

	return rc;
}

static apr_byte_t sts_add_auth_client_secret_jwt(request_rec *r,
		const char *client_id, const char *client_secret, const char *audience,
		apr_table_t *params) {
	sts_debug(r, "enter");
	cjose_err err;
	cjose_jwk_t *jwk = cjose_jwk_create_oct_spec(
			(const unsigned char *) client_secret, strlen(client_secret), &err);
	if (jwk == NULL) {
		sts_error(r, "cjose_jwk_create_oct_spec failed: %s",
				sts_cjose_e2s(r->pool, err));
		return FALSE;
	}
	return sts_add_signed_jwt_and_release_jwk(r, jwk, CJOSE_HDR_ALG_HS256,
			client_id, audience, params);
}

static apr_byte_t sts_add_auth_private_key_jwt(request_rec *r,
		const char *client_id, const char *jwk_json, const char *audience,
		apr_table_t *params) {
	sts_debug(r, "enter");
	cjose_err err;
	cjose_jwk_t *jwk = cjose_jwk_import(jwk_json, strlen(jwk_json), &err);
	if (jwk == NULL) {
		sts_error(r, "cjose_jwk_import failed: %s",
				sts_cjose_e2s(r->pool, err));
		return FALSE;
	}

	if (cjose_jwk_get_kty(jwk, &err) != CJOSE_JWK_KTY_RSA) {
		sts_error(r, "jwk is not an RSA key: %s", sts_cjose_e2s(r->pool, err));
		return FALSE;
	}

	return sts_add_signed_jwt_and_release_jwk(r, jwk, CJOSE_HDR_ALG_RS256,
			client_id, audience, params);
}

apr_byte_t sts_get_oauth_endpoint_auth(request_rec *r, int auth,
		apr_hash_t *auth_options, const char *endpoint, apr_table_t *params,
		const char *client_id, char **basic_auth, const char **client_cert,
		const char **client_key) {

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

		} else if (auth == STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT) {

			if (client_id == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR "\" the client_id must be set the configuration.");
				return FALSE;
			}
			const char *client_secret = sts_get_config_method_option(r,
					auth_options,
					STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
					STS_ENDPOINT_AUTH_OPTION_SECRET,
					NULL);
			if (client_secret == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_SECRET "\" option must be set on the configuration directive");
				return FALSE;
			}
			const char *aud = sts_get_config_method_option(r, auth_options,
					STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR,
					STS_ENDPOINT_AUTH_OPTION_AUD, endpoint);

			if (sts_add_auth_client_secret_jwt(r, client_id, client_secret, aud,
					params) == FALSE)
				return FALSE;

		} else if (auth == STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT) {

			if (client_id == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_CLIENT_SECRET_JWT_STR "\" the client_id must be set the configuration.");
				return FALSE;
			}
			const char *jwk = sts_get_config_method_option(r, auth_options,
					STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
					STS_ENDPOINT_AUTH_OPTION_JWK,
					NULL);
			if (jwk == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_JWK "\" option must be set on the configuration directive");
				return FALSE;
			}
			const char *aud = sts_get_config_method_option(r, auth_options,
					STS_ENDPOINT_AUTH_PRIVATE_KEY_JWT_STR,
					STS_ENDPOINT_AUTH_OPTION_AUD, endpoint);

			if (sts_add_auth_private_key_jwt(r, client_id, jwk, aud,
					params) == FALSE)
				return FALSE;

		}

	}
	return TRUE;
}

apr_byte_t sts_util_token_exchange(request_rec *r, const char *token,
		char **rtoken) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	int mode = sts_get_mode(r);
	if (mode == STS_CONFIG_MODE_WSTRUST)
		return sts_wstrust_exec(r, cfg, token, rtoken);
	if (mode == STS_CONFIG_MODE_ROPC)
		return sts_ropc_exec(r, cfg, token, rtoken);
	if (mode == STS_CONFIG_MODE_OTX)
		return sts_otx_exec(r, cfg, token, rtoken);
	sts_error(r, "unknown STS mode %d", mode);
	return FALSE;
}

void *sts_create_server_config(apr_pool_t *pool, server_rec *svr) {
	sts_server_config *c = apr_pcalloc(pool, sizeof(sts_server_config));

	c->merged = FALSE;
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

	c->otx_endpoint = NULL;
	c->otx_endpoint_auth = STS_CONFIG_POS_INT_UNSET;
	c->otx_endpoint_auth_options = NULL;
	c->otx_client_id = NULL;

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

	c->merged = TRUE;
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

	c->otx_endpoint =
			add->otx_endpoint != NULL ? add->otx_endpoint : base->otx_endpoint;
	c->otx_endpoint_auth =
			add->otx_endpoint_auth != STS_CONFIG_POS_INT_UNSET ?
					add->otx_endpoint_auth : base->otx_endpoint_auth;
	c->otx_endpoint_auth_options =
			add->otx_endpoint_auth_options != NULL ?
					add->otx_endpoint_auth_options :
					base->otx_endpoint_auth_options;
	c->otx_client_id =
			add->otx_client_id != NULL ?
					add->otx_client_id : base->otx_client_id;

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
	c->strip_source_token = STS_CONFIG_POS_INT_UNSET;
	c->set_target_token_in = STS_CONFIG_POS_INT_UNSET;
	c->set_target_token_in_options = NULL;
	c->request_parameters = NULL;
	c->path = apr_pstrdup(pool, path);
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
	c->strip_source_token =
			add->strip_source_token != STS_CONFIG_POS_INT_UNSET ?
					add->strip_source_token : base->strip_source_token;
	c->set_target_token_in =
			add->set_target_token_in != STS_CONFIG_POS_INT_UNSET ?
					add->set_target_token_in : base->set_target_token_in;
	c->set_target_token_in_options =
			add->set_target_token_in_options != NULL ?
					add->set_target_token_in_options :
					base->set_target_token_in_options;
	c->request_parameters =
			add->request_parameters != NULL ?
					add->request_parameters : base->request_parameters;
	c->path = add->path != NULL ? add->path : base->path;
	return c;
}

static void sts_register_hooks(apr_pool_t *p) {
	ap_hook_post_config(sts_post_config_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(sts_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(sts_post_read_request, NULL, NULL, APR_HOOK_LAST);
	static const char * const aszPre[] = { "mod_auth_openidc.c", NULL };
	ap_hook_fixups(sts_fixup_handler, aszPre, NULL, APR_HOOK_MIDDLE);
}

static const command_rec sts_cmds[] =
{

		AP_INIT_FLAG(
				STSEnabled,
				ap_set_flag_slot,
				(void*)APR_OFFSETOF(sts_dir_config, enabled),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Enable or disable mod_sts."),

		AP_INIT_TAKE1(
				STSMode,
				sts_set_mode,
				(void*)APR_OFFSETOF(sts_server_config, mode),
				RSRC_CONF,
				"Set STS mode to \"" STS_CONFIG_MODE_WSTRUST_STR "\", \"" STS_CONFIG_MODE_ROPC_STR "\" or \"" STS_CONFIG_MODE_OTX_STR "\"."),
		AP_INIT_FLAG(
				STSSSLValidateServer,
				sts_set_flag_slot,
				(void*)APR_OFFSETOF(sts_server_config, ssl_validation),
				RSRC_CONF,
				"Enable or disable SSL server certificate validation for calls to the STS."),
		AP_INIT_TAKE1(
				STSHTTPTimeOut,
				sts_set_int_slot,
				(void*)APR_OFFSETOF(sts_server_config, http_timeout),
				RSRC_CONF,
				"Timeout for calls to the STS."),

		AP_INIT_TAKE12(
				STSRequestParameter,
				sts_set_request_parameter,
				(void*)APR_OFFSETOF(sts_dir_config, request_parameters),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set extra request parameters for the token exchange request."),

		AP_INIT_TAKE1(
				STSWSTrustEndpoint,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_endpoint),
				RSRC_CONF,
				"Set the WS-Trust STS endpoint."),
		AP_INIT_TAKE1(
				STSWSTrustEndpointAuth,
				sts_set_wstrust_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the WS-Trust Endpoint."),
		AP_INIT_TAKE1(
				STSWSTrustAppliesTo,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_applies_to),
				RSRC_CONF,
				"Set the WS-Trust AppliesTo value."),
		AP_INIT_TAKE1(
				STSWSTrustTokenType,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_token_type),
				RSRC_CONF,
				"Set the WS-Trust Token Type."),
		AP_INIT_TAKE1(
				STSWSTrustValueType,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, wstrust_value_type),
				RSRC_CONF,
				"Set the WS-Trust Value Type."),

		AP_INIT_TAKE1(
				STSROPCEndpoint,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 ROPC Token Endpoint."),
		AP_INIT_TAKE1(
				STSROPCEndpointAuth,
				sts_set_ropc_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, ropc_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the ROPC Endpoint."),
		AP_INIT_TAKE1(
				STSROPCClientID,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_client_id),
				RSRC_CONF,
				"Set the Client ID for the OAuth 2.0 ROPC token request."),
		AP_INIT_TAKE1(
				STSROPCUsername,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ropc_username),
				RSRC_CONF,
				"Set the username to be used in the OAuth 2.0 ROPC token request; if left empty the client_id will be passed in the username parameter."),

		AP_INIT_TAKE1(
				STSOTXEndpoint,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, otx_endpoint),
				RSRC_CONF,
				"Set the OAuth 2.0 Token Exchange Endpoint."),
		AP_INIT_TAKE1(
				STSOTXEndpointAuth,
				sts_set_otx_endpoint_auth,
				(void*)APR_OFFSETOF(sts_server_config, otx_endpoint_auth),
				RSRC_CONF,
				"Configure how this module authenticates to the OAuth 2.0 Token Exchange Endpoint."),
		AP_INIT_TAKE1(
				STSOTXClientID,
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, otx_client_id),
				RSRC_CONF,
				"Set the Client ID for the OAuth 2.0 Token Exchange request."),

		AP_INIT_TAKE1(
				STSCacheExpiresIn,
				ap_set_int_slot,
				(void*)APR_OFFSETOF(sts_dir_config, cache_expires_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the cache expiry for access tokens in seconds."),

		AP_INIT_ITERATE(
				STSAcceptSourceTokenIn,
				sts_set_accept_source_token_in,
				(void*)APR_OFFSETOF(sts_dir_config, accept_source_token_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Configure how the source token may be presented."),

		AP_INIT_FLAG(
				STSStripSourceToken,
				ap_set_flag_slot,
				(void*)APR_OFFSETOF(sts_dir_config, strip_source_token),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Enable or disable stripping of the source token from the outgoing request."),

		AP_INIT_ITERATE(
				STSSetTargetTokenIn,
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

