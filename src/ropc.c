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

#include "mod_sts.h"

#define STS_ROPC_ENDPOINT_DEFAULT          "https://localhost:9031/as/token.oauth2"
#define STS_ROPC_ENDPOINT_AUTH_DEFAULT      STS_ENDPOINT_AUTH_NONE
#define STS_ROPC_CLIENT_ID_DEFAULT          "mod_sts"
#define STS_ROPC_USERNAME_DEFAULT           NULL

#define STS_ROPC_GRANT_TYPE_VALUE "password"
#define STS_ROPC_USERNAME         "username"
#define STS_ROPC_PASSWORD         "password"
#define STS_ROPC_AUD              "aud"

static const char * sts_ropc_get_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_endpoint == NULL)
		return STS_ROPC_ENDPOINT_DEFAULT;
	return cfg->ropc_endpoint;
}

static int sts_ropc_get_endpoint_auth(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_endpoint_auth == STS_CONFIG_POS_INT_UNSET)
		return STS_ROPC_ENDPOINT_AUTH_DEFAULT;
	return cfg->ropc_endpoint_auth;
}

static const char * sts_ropc_get_client_id(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_client_id == NULL)
		return STS_ROPC_CLIENT_ID_DEFAULT;
	return cfg->ropc_client_id;
}

static const char * sts_ropc_get_username(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_username == NULL)
		// return the client_id by default
		return sts_ropc_get_client_id(r);
	return cfg->ropc_username;
}

static apr_table_t *sts_ropc_get_request_parameters(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->ropc_request_parameters == NULL) {
		cfg->ropc_request_parameters = apr_table_make(r->server->process->pool,
				2);
	}
	return cfg->ropc_request_parameters;
}

static const char * sts_rocp_get_resource(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	return dir_cfg->resource;
}

apr_byte_t sts_exec_ropc(request_rec *r, sts_server_config *cfg,
		const char *token, char **rtoken) {

	apr_byte_t rv = FALSE;
	char *response = NULL;
	char *basic_auth = NULL;
	apr_table_t *params = NULL;
	json_t *result = NULL;
	const char *client_cert = NULL, *client_key = NULL;
	const char *client_id = sts_ropc_get_client_id(r);
	const char *username = sts_ropc_get_username(r);
	const char *resource = sts_rocp_get_resource(r);

	sts_debug(r, "enter");

	params = apr_table_make(r->pool, 4);
	apr_table_addn(params, STS_OAUTH_GRANT_TYPE, STS_ROPC_GRANT_TYPE_VALUE);
	if (sts_ropc_get_endpoint_auth(r) == STS_ENDPOINT_AUTH_NONE)
		apr_table_addn(params, STS_OAUTH_CLIENT_ID, client_id);
	if (username != NULL)
		apr_table_addn(params, STS_ROPC_USERNAME, username);
	apr_table_addn(params, STS_ROPC_PASSWORD, token);
	if ((resource != NULL) && (strcmp(resource, "") != 0))
		apr_table_addn(params, STS_ROPC_AUD, resource);

	params = apr_table_overlay(r->pool, sts_ropc_get_request_parameters(r),
			params);

	if (sts_get_oauth_endpoint_auth(r, sts_ropc_get_endpoint_auth(r),
			cfg->ropc_endpoint_auth_options, sts_ropc_get_endpoint(r), params,
			client_id, &basic_auth, &client_cert, &client_key) == FALSE)
		return FALSE;

	if (sts_util_http_post_form(r, sts_ropc_get_endpoint(r), params, basic_auth,
			sts_get_ssl_validation(r), &response, sts_get_http_timeout(r),
			NULL, client_cert, client_key) == FALSE) {
		sts_error(r, "oidc_util_http_post_form failed!");
		return FALSE;
	}

	if (sts_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	rv = sts_util_json_object_get_string(r->pool, result,
			STS_OAUTH_ACCESS_TOKEN, rtoken,
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
