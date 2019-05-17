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

#include <stdio.h>
#include <errno.h>

#include "apr.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"

#include "httpd.h"
#include "http_config.h"

#include "mod_sts.h"

extern module AP_MODULE_DECLARE_DATA sts_module;

static request_rec * test_setup(apr_pool_t *pool) {
	request_rec *request = (request_rec *) apr_pcalloc(pool,
			sizeof(request_rec));

	request->pool = pool;

	request->headers_in = apr_table_make(request->pool, 0);
	request->headers_out = apr_table_make(request->pool, 0);
	request->err_headers_out = apr_table_make(request->pool, 0);

	request->server = apr_pcalloc(request->pool, sizeof(struct server_rec));
	request->server->process = apr_pcalloc(request->pool,
			sizeof(struct process_rec));
	request->server->process->pool = request->pool;
	request->connection = apr_pcalloc(request->pool, sizeof(struct conn_rec));
	request->connection->local_addr = apr_pcalloc(request->pool,
			sizeof(apr_sockaddr_t));

	apr_pool_userdata_set("https", "scheme", NULL, request->pool);
	request->server->server_hostname = "www.example.com";
	request->connection->local_addr->port = 443;
	request->unparsed_uri = "/bla?foo=bar&param1=value1";
	request->args = "foo=bar&param1=value1";
	apr_uri_parse(request->pool,
			"https://www.example.com/bla?foo=bar&param1=value1",
			&request->parsed_uri);

	sts_module.module_index = 0;
	sts_server_config *cfg = sts_create_server_config(request->pool,
			request->server);
	cfg->ssl_validation = 0;
	cfg->mode = 0;
	cfg->wstrust_endpoint = "https://localhost:9031/pf/sts.wst";
	cfg->wstrust_applies_to = "localhost:default:entityId";
	//cfg->wstrust_token_type = "urn:bogus:token";
	cfg->wstrust_token_type = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
	cfg->wstrust_value_type =
			"urn:pingidentity.com:oauth2:grant_type:validate_bearer";

	sts_dir_config *d_cfg = sts_create_dir_config(request->pool, NULL);
	d_cfg->enabled = 1;

	request->server->module_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * 1);
	request->per_dir_config = apr_pcalloc(request->pool,
			sizeof(ap_conf_vector_t *) * 1);
	ap_set_module_config(request->server->module_config, &sts_module, cfg);
	ap_set_module_config(request->per_dir_config, &sts_module, d_cfg);

	return request;
}

int main(int argc, char **argv, char **env) {
	if (apr_app_initialize(&argc, (const char * const **) argv,
			(const char * const **) env) != APR_SUCCESS) {
		printf("apr_app_initialize failed\n");
		return -1;
	}

	if (argc < 2) {
		printf(" Usage: %s <access_token>\n", argv[0]);
		exit(0);
	}

	apr_pool_t *pool = NULL;
	apr_pool_create(&pool, NULL);

	request_rec *r = test_setup(pool);

	if (sts_config_check_vhost_config(pool, r->server) != OK) {
		printf("configuration error\n");
		exit(-1);
	}

	char *token = argv[1];
	char *response = NULL;

	apr_byte_t result = sts_util_token_exchange(r, token, &response);

	if (result == TRUE) {
		printf("Success: %s\n", response);
	} else {
		printf("Failure: %s\n", response);
	}

	apr_pool_destroy(pool);
	apr_terminate();

	return result != 0;
}

