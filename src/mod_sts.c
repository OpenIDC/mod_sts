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

#include <httpd.h>
#include <http_config.h>
#include <http_request.h>
#include <http_protocol.h>

#include <apr_hooks.h>
#include <apr_optional.h>
#include <apr_base64.h>
#include <apr_lib.h>

#include "mod_sts.h"
#include "curl/curl.h"

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "jansson.h"

//module AP_MODULE_DECLARE_DATA sts_module;

#define STS_CONFIG_POS_INT_UNSET                -1
#define STS_CONFIG_DEFAULT_ENABLED              1

#define STS_CONFIG_DEFAULT_WSTRUST_STS_URL      "https://localhost:9031/pf/sts.wst"
#define STS_CONFIG_DEFAULT_WSTRUST_APPLIES_TO   "localhost:default:entityId"
#define STS_CONFIG_DEFAULT_WSTRUST_TOKEN_TYPE   "urn:bogus:token"
//#define STS_CONFIG_DEFAULT_WSTRUST_TOKEN_TYPE "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"

#define STS_CONFIG_DEFAULT_WSTRUST_VALUE_TYPE   "urn:pingidentity.com:oauth2:grant_type:validate_bearer"
#define STS_CONFIG_DEFAULT_WSTRUST_ACTION       "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
#define STS_CONFIG_DEFAULT_WSTRUST_REQUEST_TYPE "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
#define STS_CONFIG_DEFAULT_WSTRUST_KEY_TYPE     "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"

#define STS_CONFIG_DEFAULT_ROPC_TOKEN_ENDPOINT  "https://localhost:9031/as/token.oauth2"
#define STS_CONFIG_DEFAULT_ROPC_CLIENT_ID       "mod_sts"
#define STS_CONFIG_DEFAULT_ROPC_USERNAME        NULL

#define STS_CONFIG_DEFAULT_IETF_TOKEN_ENDPOINT  "https://localhost:9031/as/token.oauth2"

#define STS_CONFIG_DEFAULT_CACHE_SHM_SIZE       2048
#define STS_CONFIG_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 4096 + 512 + 17

#define STS_CONFIG_DEFAULT_CACHE_EXPIRES_IN     300

#define STS_CONFIG_DEFAULT_COOKIE_NAME          "sts_cookie"

#define STS_CONFIG_MODE_WSTRUST                 0
#define STS_CONFIG_MODE_ROPC                    1
#define STS_CONFIG_MODE_TOKEN_EXCHANGE          2

#define STS_CONFIG_DEFAULT_STS_MODE             STS_CONFIG_MODE_WSTRUST

#define STS_CONFIG_ACCEPT_TOKEN_IN_ENVIRONMENT  1
#define STS_CONFIG_ACCEPT_TOKEN_IN_HEADER       2
#define STS_CONFIG_ACCEPT_TOKEN_IN_QUERY        4
#define STS_CONFIG_ACCEPT_TOKEN_IN_COOKIE       8

#define STS_CONFIG_DEFAULT_ACCEPT_TOKEN_IN      (STS_CONFIG_ACCEPT_TOKEN_IN_ENVIRONMENT | STS_CONFIG_ACCEPT_TOKEN_IN_HEADER)

#define STS_CACHE_SECTION                       "sts"

#define STS_CONFIG_DEFAULT_SSL_VALIDATION       1
#define STS_CONFIG_DEFAULT_HTTP_TIMEOUT         20

#define STS_CONTENT_TYPE_FORM_ENCODED           "application/x-www-form-urlencoded"

#define STS_HEADER_COOKIE                       "Cookie"
#define STS_HEADER_SOAP_ACTION                  "soapAction"
#define STS_HEADER_CONTENT_TYPE                 "Content-Type"

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
	if (strcmp(arg, "wstrust") == 0) {
		cfg->mode = STS_CONFIG_MODE_WSTRUST;
		return NULL;
	}
	if (strcmp(arg, "ropc") == 0) {
		cfg->mode = STS_CONFIG_MODE_ROPC;
		return NULL;
	}
	if (strcmp(arg, "tokenexchange") == 0) {
		cfg->mode = STS_CONFIG_MODE_TOKEN_EXCHANGE;
		return NULL;
	}

	return "Invalid value: must be \"wstrust\", \"ropc\" or \"tokenexchange\"";
}

static const char *sts_set_accept_token_in(cmd_parms *cmd, void *m,
		const char *arg) {
	sts_dir_config *dir_cfg = (sts_dir_config *) m;

	int v = STS_CONFIG_POS_INT_UNSET;

	if (strcmp(arg, "environment") == 0)
		v = STS_CONFIG_ACCEPT_TOKEN_IN_ENVIRONMENT;
	if (strcmp(arg, "header") == 0)
		v = STS_CONFIG_ACCEPT_TOKEN_IN_HEADER;
	if (strcmp(arg, "query") == 0)
		v = STS_CONFIG_ACCEPT_TOKEN_IN_QUERY;
	if (strcmp(arg, "cookie") == 0)
		v = STS_CONFIG_ACCEPT_TOKEN_IN_COOKIE;

	if (v != STS_CONFIG_POS_INT_UNSET) {
		if (dir_cfg->accept_token_in == STS_CONFIG_POS_INT_UNSET)
			dir_cfg->accept_token_in = v;
		else
			dir_cfg->accept_token_in |= v;
		return NULL;
	}

	return "Invalid value: must be \"environment\", \"header\", \"query\" or \"cookie\"";
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

static const char * sts_get_ietf_token_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ietf_token_endpoint == NULL)
		return STS_CONFIG_DEFAULT_IETF_TOKEN_ENDPOINT;
	return cfg->ietf_token_endpoint;
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

static char * sts_get_cookie_name(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->cookie_name == NULL)
		return STS_CONFIG_DEFAULT_COOKIE_NAME;
	return dir_cfg->cookie_name;
}

static int sts_get_mode(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->mode == STS_CONFIG_POS_INT_UNSET) {
		return STS_CONFIG_DEFAULT_STS_MODE;
	}
	return cfg->mode;
}

static int sts_get_accept_token_in(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->accept_token_in == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_ACCEPT_TOKEN_IN;
	return dir_cfg->accept_token_in;
}

char *sts_util_unescape_string(const request_rec *r, const char *str) {
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		sts_error(r, "curl_easy_init() error");
		return NULL;
	}
	int counter = 0;
	char *replaced = (char *) str;
	while (str[counter] != '\0') {
		if (str[counter] == '+') {
			replaced[counter] = ' ';
		}
		counter++;
	}
	char *result = curl_easy_unescape(curl, replaced, 0, 0);
	if (result == NULL) {
		sts_error(r, "curl_easy_unescape() error");
		return NULL;
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	//sts_debug(r, "input=\"%s\", output=\"%s\"", str, rv);
	return rv;
}

apr_byte_t sts_util_read_form_encoded_params(request_rec *r, apr_table_t *table,
		char *data) {
	const char *key, *val, *p = data;

	while (p && *p && (val = ap_getword(r->pool, &p, '&'))) {
		key = ap_getword(r->pool, &val, '=');
		key = sts_util_unescape_string(r, key);
		val = sts_util_unescape_string(r, val);
		sts_debug(r, "read: %s=%s", key, val);
		apr_table_set(table, key, val);
	}

	sts_debug(r, "parsed: %d bytes into %d elements",
			data ? (int )strlen(data) : 0, apr_table_elts(table)->nelts);

	return TRUE;
}

char *sts_util_get_cookie(request_rec *r, const char *cookieName) {
	char *cookie, *tokenizerCtx, *rv = NULL;

	char *cookies = apr_pstrdup(r->pool,
			apr_table_get(r->headers_in, STS_HEADER_COOKIE));

	if (cookies != NULL) {

		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, ";", &tokenizerCtx);

		while (cookie != NULL) {

			while (*cookie == ' ')
				cookie++;

			/* see if we've found the cookie that we're looking for */
			if ((strncmp(cookie, cookieName, strlen(cookieName)) == 0)
					&& (cookie[strlen(cookieName)] == '=')) {

				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (strlen(cookieName) + 1);
				rv = apr_pstrdup(r->pool, cookie);

				break;
			}

			/* go to the next cookie */
			cookie = apr_strtok(NULL, ";", &tokenizerCtx);
		}
	}

	/* log what we've found */
	sts_debug(r, "returning \"%s\" = %s", cookieName,
			rv ? apr_psprintf(r->pool, "\"%s\"", rv) : "<null>");

	return rv;
}

#define STS_OIDC_ACCESS_TOKEN_ENV_NAME "OIDC_access_token"

static char *sts_get_access_token_from_environment(request_rec *r) {
	sts_debug(r, "enter");

	char *access_token = apr_pstrdup(r->pool,
			apr_table_get(r->subprocess_env, STS_OIDC_ACCESS_TOKEN_ENV_NAME));
	if (access_token == NULL) {
		sts_debug(r,
				"no access_token found in %s subprocess environment variables",
				STS_OIDC_ACCESS_TOKEN_ENV_NAME);
	}

	return access_token;
}

#define STS_HEADER_AUTHORIZATION         "Authorization"
#define STS_HEADER_AUTHORIZATION_BEARER  "Bearer"

static char *sts_get_access_token_from_header(request_rec *r) {
	sts_debug(r, "enter");
	char *access_token = NULL;
	const char *auth_line = apr_table_get(r->headers_in,
			STS_HEADER_AUTHORIZATION);
	if (auth_line) {
		sts_debug(r, "%s header found", STS_HEADER_AUTHORIZATION);
		if (apr_strnatcasecmp(ap_getword(r->pool, &auth_line, ' '),
				STS_HEADER_AUTHORIZATION_BEARER) == 0) {
			while (apr_isspace(*auth_line))
				auth_line++;
			access_token = apr_pstrdup(r->pool, auth_line);
		} else {
			sts_warn(r, "client used unsupported authentication scheme: %s",
					r->uri);
		}
	}
	return access_token;
}

#define STS_ACCESS_TOKEN_QUERY_PARAM_NAME "access_token"

static char *sts_get_access_token_from_query(request_rec *r) {
	sts_debug(r, "enter");
	char *access_token = NULL;

	apr_table_t *params = apr_table_make(r->pool, 8);
	sts_util_read_form_encoded_params(r, params, r->args);
	access_token = apr_pstrdup(r->pool,
			apr_table_get(params, STS_ACCESS_TOKEN_QUERY_PARAM_NAME));

	return access_token;
}

#define STS_ACCESS_TOKEN_COOKIE_NAME "PA.global"

static char *sts_get_access_token_from_cookie(request_rec *r) {
	sts_debug(r, "enter");
	char *access_token = sts_util_get_cookie(r, STS_ACCESS_TOKEN_COOKIE_NAME);
	return access_token;
}

static const char *sts_get_access_token(request_rec *r) {

	const char *access_token = NULL;

	int accept_token_in = sts_get_accept_token_in(r);
	sts_debug(r, "accept_token_in: %d", accept_token_in);

	if ((access_token == NULL)
			&& (accept_token_in & STS_CONFIG_ACCEPT_TOKEN_IN_ENVIRONMENT))
		access_token = sts_get_access_token_from_environment(r);

	if ((access_token == NULL)
			&& (accept_token_in & STS_CONFIG_ACCEPT_TOKEN_IN_HEADER))
		access_token = sts_get_access_token_from_header(r);

	if ((access_token == NULL)
			&& (accept_token_in & STS_CONFIG_ACCEPT_TOKEN_IN_QUERY))
		access_token = sts_get_access_token_from_query(r);

	if ((access_token == NULL)
			&& (accept_token_in & STS_CONFIG_ACCEPT_TOKEN_IN_COOKIE))
		access_token = sts_get_access_token_from_cookie(r);

	if (access_token == NULL) {
		sts_debug(r,
				"no access_token found in any of the configured methods: %d",
				accept_token_in);
	}

	return access_token;
}

static int sts_handler(request_rec *r) {
	sts_debug(r, "enter");

	if (sts_get_enabled(r) != 1) {
		sts_debug(r, "disabled");
		return DECLINED;
	}

	const char *access_token = sts_get_access_token(r);
	if (access_token == NULL)
		return DECLINED;

	char *sts_token = NULL;
	sts_cache_shm_get(r, STS_CACHE_SECTION, access_token, &sts_token);

	if (sts_token == NULL) {
		sts_debug(r, "cache miss");
		if (sts_util_http_token_exchange(r, access_token, NULL,
				sts_get_ssl_validation(r), &sts_token) == FALSE) {
			sts_error(r, "sts_util_http_token_exchange failed");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		sts_cache_shm_set(r, STS_CACHE_SECTION, access_token, sts_token,
				apr_time_now() + apr_time_from_sec(sts_get_cache_expires_in(r)));
	}

	sts_debug(r, "set cookie to backend: %s=%s", sts_get_cookie_name(r),
			sts_token);
	// TODO: add the cookie to the existing ones instead of overwriting/replacing existing cookies?
	apr_table_set(r->headers_in, "Cookie",
			apr_psprintf(r->pool, "%s=%s", sts_get_cookie_name(r), sts_token));

	return OK;
}

static int sts_post_read_request(request_rec *r) {
	sts_debug(r, "enter");
	return DECLINED;
}

static int sts_fixup_handler(request_rec *r) {
	sts_debug(r, "enter");
	return sts_handler(r);
}

typedef struct sts_curl_buffer {
	request_rec *r;
	char *memory;
	size_t size;
} sts_curl_buffer;

#define STS_CURL_MAX_RESPONSE_SIZE 1024 * 1024

size_t sts_curl_write(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	sts_curl_buffer *mem = (sts_curl_buffer *) userp;

	/* check if we don't run over the maximum buffer/memory size for HTTP responses */
	if (mem->size + realsize > STS_CURL_MAX_RESPONSE_SIZE) {
		sts_error(mem->r,
				"HTTP response larger than maximum allowed size: current size=%ld, additional size=%ld, max=%d",
				mem->size, realsize, STS_CURL_MAX_RESPONSE_SIZE);
		return 0;
	}

	/* allocate the new buffer for the current + new response bytes */
	char *newptr = apr_palloc(mem->r->pool, mem->size + realsize + 1);
	if (newptr == NULL) {
		sts_error(mem->r,
				"memory allocation for new buffer of %ld bytes failed",
				mem->size + realsize + 1);
		return 0;
	}

	/* copy over the data from current memory plus the cURL buffer */
	memcpy(newptr, mem->memory, mem->size);
	memcpy(&(newptr[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory = newptr;
	mem->memory[mem->size] = 0;

	return realsize;
}

#define STS_CURL_USER_AGENT     "mod_sts"

static apr_byte_t sts_util_http_call(request_rec *r, const char *url,
		const char *data, const char *content_type, const char *basic_auth,
		const char *soap_action, int ssl_validate_server, char **response,
		int timeout, const char *outgoing_proxy, const char *ssl_cert,
		const char *ssl_key) {
	char curlError[CURL_ERROR_SIZE];
	sts_curl_buffer curlBuffer;
	CURL *curl;
	struct curl_slist *h_list = NULL;

	/* do some logging about the inputs */
	sts_debug(r,
			"url=%s, data=%s, content_type=%s, soap_action=%s, bearer_token=%s, ssl_validate_server=%d, timeout=%d",
			url, data, content_type, basic_auth, soap_action,
			ssl_validate_server, timeout);

	curl = curl_easy_init();
	if (curl == NULL) {
		sts_error(r, "curl_easy_init() error");
		return FALSE;
	}

	/* set the error buffer as empty before performing a request */
	curlError[0] = 0;

	/* some of these are not really required */
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

	/* set the timeout */
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

	/* setup the buffer where the response will be written to */
	curlBuffer.r = r;
	curlBuffer.memory = NULL;
	curlBuffer.size = 0;
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sts_curl_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void * )&curlBuffer);

#ifndef LIBCURL_NO_CURLPROTO
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
			CURLPROTO_HTTP|CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif

	/* set the options for validating the SSL server certificate that the remote site presents */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
			(ssl_validate_server != 0 ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			(ssl_validate_server != 0 ? 2L : 0L));

#ifdef WIN32
	DWORD buflen;
	char *ptr = NULL;
	char *retval = (char *) malloc(sizeof (TCHAR) * (MAX_PATH + 1));
	retval[0] = '\0';
	buflen = SearchPath(NULL, "curl-ca-bundle.crt", NULL, MAX_PATH+1, retval, &ptr);
	if (buflen > 0)
		curl_easy_setopt(curl, CURLOPT_CAINFO, retval);
	else
		sts_warn(r, "no curl-ca-bundle.crt file found in path");
	free(retval);
#endif

	/* identify this HTTP client */
	curl_easy_setopt(curl, CURLOPT_USERAGENT, STS_CURL_USER_AGENT);

	/* set optional outgoing proxy for the local network */
	if (outgoing_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, outgoing_proxy);
	}

	/* see if we need to add a soap action header */
	if (soap_action != NULL) {
		h_list = curl_slist_append(h_list,
				apr_psprintf(r->pool, "%s: %s", STS_HEADER_SOAP_ACTION,
						soap_action));
	}

	/* see if we need to perform HTTP basic authentication to the remote site */
	if (basic_auth != NULL) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERPWD, basic_auth);
	}

	if (ssl_cert != NULL)
		curl_easy_setopt(curl, CURLOPT_SSLCERT, ssl_cert);
	if (ssl_key != NULL)
		curl_easy_setopt(curl, CURLOPT_SSLKEY, ssl_key);

	if (data != NULL) {
		/* set POST data */
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		/* set HTTP method to POST */
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	if (content_type != NULL) {
		/* set content type */
		h_list = curl_slist_append(h_list,
				apr_psprintf(r->pool, "%s: %s", STS_HEADER_CONTENT_TYPE,
						content_type));
	}

	/* see if we need to add any custom headers */
	if (h_list != NULL)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h_list);

	/* set the target URL */
	curl_easy_setopt(curl, CURLOPT_URL, url);

	/* call it and record the result */
	int rv = TRUE;
	if (curl_easy_perform(curl) != CURLE_OK) {
		sts_error(r, "curl_easy_perform() failed on: %s (%s)", url,
				curlError[0] ? curlError : "");
		rv = FALSE;
		goto out;
	}

	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	sts_debug(r, "HTTP response code=%ld", response_code);

	*response = apr_pstrndup(r->pool, curlBuffer.memory, curlBuffer.size);

	/* set and log the response */
	sts_debug(r, "response=%s", *response ? *response : "");

	out:

	/* cleanup and return the result */
	if (h_list != NULL)
		curl_slist_free_all(h_list);
	curl_easy_cleanup(curl);

	return rv;
}

static char *sts_util_escape_string(const request_rec *r, const char *str) {
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		sts_error(r, "curl_easy_init() error");
		return NULL;
	}
	char *result = curl_easy_escape(curl, str, 0);
	if (result == NULL) {
		sts_error(r, "curl_easy_escape() error");
		return NULL;
	}
	char *rv = apr_pstrdup(r->pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	return rv;
}

typedef struct sts_http_encode_t {
	request_rec *r;
	char *encoded_params;
} sts_http_encode_t;

static int sts_util_http_add_form_url_encoded_param(void* rec, const char* key,
		const char* value) {
	sts_http_encode_t *ctx = (sts_http_encode_t*) rec;
	sts_debug(ctx->r, "processing: %s=%s", key, value);
	const char *sep = ctx->encoded_params ? "&" : "";
	ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s%s=%s",
			ctx->encoded_params ? ctx->encoded_params : "", sep,
					sts_util_escape_string(ctx->r, key),
					sts_util_escape_string(ctx->r, value));
	return 1;
}

static char *sts_util_http_form_encoded_data(request_rec *r,
		const apr_table_t *params) {
	char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		sts_http_encode_t encode_data = { r, NULL };
		apr_table_do(sts_util_http_add_form_url_encoded_param, &encode_data,
				params,
				NULL);
		data = encode_data.encoded_params;
	}
	sts_debug(r, "data=%s", data);
	return data;
}

apr_byte_t sts_util_http_post_form(request_rec *r, const char *url,
		const apr_table_t *params, const char *basic_auth,
		int ssl_validate_server, char **response, int timeout,
		const char *outgoing_proxy, const char *ssl_cert, const char *ssl_key) {
	char *data = sts_util_http_form_encoded_data(r, params);
	return sts_util_http_call(r, url, data,
			STS_CONTENT_TYPE_FORM_ENCODED, basic_auth, NULL, ssl_validate_server,
			response, timeout, outgoing_proxy, ssl_cert, ssl_key);
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

static apr_byte_t sts_util_http_wstrust(request_rec *r, const char *token,
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

apr_byte_t sts_util_decode_json_object(request_rec *r, const char *str,
		json_t **json) {

	if (str == NULL)
		return FALSE;

	json_error_t json_error;
	*json = json_loads(str, 0, &json_error);

	/* decode the JSON contents of the buffer */
	if (*json == NULL) {
		/* something went wrong */
		sts_error(r, "JSON parsing returned an error: %s (%s)", json_error.text,
				str);
		return FALSE;
	}

	if (!json_is_object(*json)) {
		/* oops, no JSON */
		sts_error(r, "parsed JSON did not contain a JSON object");
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

char *sts_util_encode_json_object(request_rec *r, json_t *json, size_t flags) {
	char *s = json_dumps(json, flags);
	char *s_value = apr_pstrdup(r->pool, s);
	free(s);
	return s_value;
}

static apr_byte_t sts_util_json_string_print(request_rec *r, json_t *result,
		const char *key, const char *log) {
	json_t *value = json_object_get(result, key);
	if (value != NULL && !json_is_null(value)) {
		sts_error(r,
				"%s: response contained an \"%s\" entry with value: \"%s\"",
				log, key,
				sts_util_encode_json_object(r, value, JSON_ENCODE_ANY));
		return TRUE;
	}
	return FALSE;
}

static apr_byte_t sts_util_check_json_error(request_rec *r, json_t *json) {
	if (sts_util_json_string_print(r, json, "error",
			"oidc_util_check_json_error") == TRUE) {
		sts_util_json_string_print(r, json, "error_description",
				"oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}

apr_byte_t sts_util_decode_json_and_check_error(request_rec *r, const char *str,
		json_t **json) {

	if (sts_util_decode_json_object(r, str, json) == FALSE)
		return FALSE;

	// see if it is not an error response somehow
	if (sts_util_check_json_error(r, *json) == TRUE) {
		json_decref(*json);
		*json = NULL;
		return FALSE;
	}

	return TRUE;
}

apr_byte_t sts_json_object_get_string(apr_pool_t *pool, json_t *json,
		const char *name, char **value, const char *default_value) {
	*value = default_value ? apr_pstrdup(pool, default_value) : NULL;
	if (json != NULL) {
		json_t *v = json_object_get(json, name);
		if ((v != NULL) && (json_is_string(v))) {
			*value = apr_pstrdup(pool, json_string_value(v));
		}
	}
	return TRUE;
}

#define STS_ROPC_GRANT_TYPE_NAME  "grant_type"
#define STS_ROPC_GRANT_TYPE_VALUE "password"
#define STS_ROPC_CLIENT_ID        "client_id"
#define STS_ROPC_USERNAME         "username"
#define STS_ROPC_PASSWORD         "password"
#define STS_ROPC_ACCESS_TOKEN     "access_token"

static apr_byte_t sts_util_http_ropc(request_rec *r, const char *token,
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

	apr_byte_t rv = sts_json_object_get_string(r->pool, result,
			STS_ROPC_ACCESS_TOKEN, rtoken,
			NULL);
	/*
	 char **token_type = NULL;
	 oidc_json_object_get_string(r->pool, result, "token_type",
	 token_type,
	 NULL);

	 if (token_type != NULL) {
	 if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE) {
	 oidc_warn(r, "access token type did not validate, dropping it");
	 *access_token = NULL;
	 }
	 }

	 oidc_json_object_get_int(r->pool, result, OIDC_PROTO_EXPIRES_IN, expires_in,
	 -1);

	 oidc_json_object_get_string(r->pool, result, OIDC_PROTO_REFRESH_TOKEN,
	 refresh_token,
	 NULL);
	 */

	json_decref(result);

	return rv;
}

#define STS_IETF_GRANT_TYPE_NAME          "grant_type"
#define STS_IETF_GRANT_TYPE_VALUE         "urn:ietf:params:oauth:grant-type:token-exchange"
#define STS_IETF_RESOURCE_NAME            "resource"
#define STS_IETF_SUBJECT_TOKEN_NAME       "subject_token"
#define STS_IETF_SUBJECT_TOKEN_TYPE_NAME  "subject_token_type"
#define STS_IETF_SUBJECT_TOKEN_TYPE_VALUE "urn:ietf:params:oauth:token-type:access_token"
#define STS_IETF_ACCESS_TOKEN             "access_token"

static apr_byte_t sts_util_http_ietf_token_exchange(request_rec *r,
		const char *token, const char *basic_auth, int ssl_validate_server,
		char **rtoken) {

	char *response = NULL;

	sts_debug(r, "enter");

	// TODO:
	char *resource = NULL;

	/*
	 example from IETF draft:

	 grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
	 &resource=https%3A%2F%2Fbackend.example.com%2Fapi%20
	 &subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
	 &subject_token_type=
	 urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
	 */

	apr_table_t *data = apr_table_make(r->pool, 4);
	apr_table_addn(data, STS_IETF_GRANT_TYPE_NAME, STS_IETF_GRANT_TYPE_VALUE);
	if (resource != NULL)
		apr_table_addn(data, STS_IETF_RESOURCE_NAME, resource);
	apr_table_addn(data, STS_IETF_SUBJECT_TOKEN_NAME, token);
	apr_table_addn(data, STS_IETF_SUBJECT_TOKEN_TYPE_NAME,
			STS_IETF_SUBJECT_TOKEN_TYPE_VALUE);

	if (sts_util_http_post_form(r, sts_get_ietf_token_endpoint(r), data,
			basic_auth, ssl_validate_server, &response, sts_get_http_timeout(r),
			NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "oidc_util_http_post_form failed!");
		return FALSE;
	}

	json_t *result = NULL;
	if (sts_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	apr_byte_t rv = sts_json_object_get_string(r->pool, result,
			STS_IETF_ACCESS_TOKEN, rtoken,
			NULL);

	json_decref(result);

	return rv;
}

apr_byte_t sts_util_http_token_exchange(request_rec *r, const char *token,
		const char *basic_auth, int ssl_validate_server, char **rtoken) {
	int mode = sts_get_mode(r);
	if (mode == STS_CONFIG_MODE_WSTRUST)
		return sts_util_http_wstrust(r, token, basic_auth, ssl_validate_server,
				rtoken);
	if (mode == STS_CONFIG_MODE_ROPC)
		return sts_util_http_ropc(r, token, basic_auth, ssl_validate_server,
				rtoken);
	if (mode == STS_CONFIG_MODE_TOKEN_EXCHANGE)
		return sts_util_http_ietf_token_exchange(r, token, basic_auth,
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

	c->ietf_token_endpoint = NULL;

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

	c->ietf_token_endpoint =
			add->ietf_token_endpoint != NULL ?
					add->ietf_token_endpoint : base->ietf_token_endpoint;

	c->cache_cfg = add->cache_cfg != NULL ? add->cache_cfg : base->cache_cfg;
	//c->cache_shm_size_max = add->cache_shm_size_max != STS_CONFIG_POS_INT_UNSET ? add->cache_shm_size_max : base->cache_shm_size_max;
	//c->cache_shm_entry_size_max = add->cache_shm_entry_size_max != STS_CONFIG_POS_INT_UNSET ? add->cache_shm_entry_size_max : base->cache_shm_entry_size_max;
	return c;
}

void *sts_create_dir_config(apr_pool_t *pool, char *path) {
	sts_dir_config *c = apr_pcalloc(pool, sizeof(sts_dir_config));
	c->enabled = STS_CONFIG_POS_INT_UNSET;
	c->cache_expires_in = STS_CONFIG_POS_INT_UNSET;
	c->cookie_name = NULL;
	c->accept_token_in = STS_CONFIG_POS_INT_UNSET;
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
	c->cookie_name =
			add->cookie_name != NULL ? add->cookie_name : base->cookie_name;
	c->accept_token_in =
			add->accept_token_in != STS_CONFIG_POS_INT_UNSET ?
					add->accept_token_in : base->accept_token_in;
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
				"Set STS mode to \"wstrust\", \"ropc\" or \"tokenexchange\"."),
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
				"STSIETFTokenEndpoint",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, ietf_token_endpoint),
				RSRC_CONF,
				"Set the IETF Token Exchange Endpoint."),

		AP_INIT_TAKE1(
				"STSCacheExpiresIn",
				ap_set_int_slot,
				(void*)APR_OFFSETOF(sts_dir_config, cache_expires_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the cache expiry for access tokens in seconds."),
		AP_INIT_TAKE1(
				"STSCookieName",
				ap_set_string_slot,
				(void*)APR_OFFSETOF(sts_dir_config, cookie_name),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Set the cookie name in which the returned token is passed to the backend."),

		AP_INIT_ITERATE(
				"STSAcceptTokenIn",
				sts_set_accept_token_in,
				(void*)APR_OFFSETOF(sts_dir_config, accept_token_in),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Configure how the access token may be presented; must be one or more of \"environment\", \"header\", \"query\" or \"cookie\"."),

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

