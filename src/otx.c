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
 * Copyright (C) 2017-2019 ZmartZone IAM
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

//#define STS_OTX_ENDPOINT_DEFAULT         "https://localhost:9031/as/token.oauth2"
#define STS_OTX_ENDPOINT_DEFAULT         NULL
#define STS_OTX_ENDPOINT_AUTH_DEFAULT    STS_ENDPOINT_AUTH_NONE
#define STS_OTX_CLIENT_ID_DEFAULT        NULL

#define STS_OTX_GRANT_TYPE_NAME          "grant_type"
#define STS_OTX_GRANT_TYPE_VALUE         "urn:ietf:params:oauth:grant-type:token-exchange"
#define STS_OTX_SUBJECT_TOKEN_NAME       "subject_token"
#define STS_OTX_SUBJECT_TOKEN_TYPE_NAME  "subject_token_type"
#define STS_OTX_SUBJECT_TOKEN_TYPE_VALUE "urn:ietf:params:oauth:token-type:access_token"
#define STS_OTX_ACCESS_TOKEN             "access_token"

int sts_otx_config_check_vhost(apr_pool_t *pool, server_rec *s,
		sts_server_config *cfg) {
	if (cfg->otx_endpoint == NULL) {
		sts_serror(s,
				STSOTXEndpoint " must be set in OAuth 2.0 Token Exchange mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

static const char * sts_otx_get_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->otx_endpoint == NULL)
		return STS_OTX_ENDPOINT_DEFAULT;
	return cfg->otx_endpoint;
}

static int sts_otx_get_endpoint_auth(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->otx_endpoint_auth == STS_CONFIG_POS_INT_UNSET)
		return STS_OTX_ENDPOINT_AUTH_DEFAULT;
	return cfg->otx_endpoint_auth;
}

static const char * sts_otx_get_client_id(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->otx_client_id == NULL)
		return STS_OTX_CLIENT_ID_DEFAULT;
	return cfg->otx_client_id;
}

static apr_table_t *sts_otx_merge_request_parameters(request_rec *r,
		apr_table_t *params) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->request_parameters == NULL) {
		dir_cfg->request_parameters = apr_table_make(r->server->process->pool,
				1);
		apr_table_set(dir_cfg->request_parameters,
				STS_OTX_SUBJECT_TOKEN_TYPE_NAME,
				STS_OTX_SUBJECT_TOKEN_TYPE_VALUE);
	}
	return apr_table_overlay(r->pool, dir_cfg->request_parameters, params);
}

apr_byte_t sts_otx_exec(request_rec *r, sts_server_config *cfg,
		const char *token, char **rtoken) {

	apr_byte_t rv = FALSE;
	char *response = NULL;
	char *basic_auth = NULL;
	apr_table_t *params = NULL;
	json_t *result = NULL;
	const char *client_cert = NULL, *client_key = NULL;
	const char *client_id = sts_otx_get_client_id(r);

	sts_debug(r, "enter");

	params = apr_table_make(r->pool, 4);
	apr_table_addn(params, STS_OTX_GRANT_TYPE_NAME,
			STS_OTX_GRANT_TYPE_VALUE);
	apr_table_addn(params, STS_OTX_SUBJECT_TOKEN_NAME, token);
	// TODO: this is not really specified...
	if ((sts_otx_get_endpoint_auth(r) == STS_ENDPOINT_AUTH_NONE)
			&& (client_id != NULL))
		apr_table_addn(params, STS_OAUTH_CLIENT_ID, client_id);

	params = sts_otx_merge_request_parameters(r, params);

	if (sts_get_oauth_endpoint_auth(r, sts_otx_get_endpoint_auth(r),
			cfg->otx_endpoint_auth_options, sts_otx_get_endpoint(r), params,
			client_id, &basic_auth, &client_cert, &client_key) == FALSE)
		return FALSE;

	if (sts_util_http_post_form(r, sts_otx_get_endpoint(r), params, basic_auth,
			sts_get_ssl_validation(r), &response, sts_get_http_timeout(r),
			NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "oidc_util_http_post_form failed!");
		return FALSE;
	}

	if (sts_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	rv = sts_util_json_object_get_string(r->pool, result,
			STS_OTX_ACCESS_TOKEN, rtoken,
			NULL);

	json_decref(result);

	return rv;
}
