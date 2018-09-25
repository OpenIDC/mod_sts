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

#ifndef MOD_STS_H_
#define MOD_STS_H_

#include <http_log.h>

#include <apr_strings.h>
#include <apr_hash.h>

#include <jansson.h>

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(sts);
#endif

#ifndef NAMEVER
#define NAMEVERSION "mod_sts-0.0.0"
#else
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define NAMEVERSION TOSTRING(NAMEVER)
#endif

#define sts_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"# %s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define sts_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "## %s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

#define sts_debug(r, fmt, ...) sts_log(r, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define sts_info(r, fmt, ...)  sts_log(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define sts_warn(r, fmt, ...)  sts_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define sts_error(r, fmt, ...) sts_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define sts_sdebug(s, fmt, ...) sts_slog(s, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define sts_sinfo(r, fmt, ...)  sts_slog(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define sts_swarn(s, fmt, ...) sts_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define sts_serror(s, fmt, ...) sts_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

#define STS_HEADER_COOKIE                       "Cookie"
#define STS_HEADER_SOAP_ACTION                  "soapAction"
#define STS_HEADER_CONTENT_TYPE                 "Content-Type"
#define STS_HEADER_HOST                         "Host"
#define STS_HEADER_X_FORWARDED_PROTO            "X-Forwarded-Proto"
#define STS_HEADER_X_FORWARDED_HOST             "X-Forwarded-Host"
#define STS_HEADER_X_FORWARDED_PORT             "X-Forwarded-Port"

#define STS_CONTENT_TYPE_FORM_ENCODED           "application/x-www-form-urlencoded"

typedef struct {
	int mode;
	int ssl_validation;
	int http_timeout;

	char *wstrust_sts_url;
	char *wstrust_applies_to;
	char *wstrust_token_type;
	char *wstrust_value_type;

	char *ropc_token_endpoint;
	char *ropc_client_id;
	char *ropc_username;

	char *ietf_token_endpoint;

	void *cache_cfg;
	int cache_shm_size_max;
	int cache_shm_entry_size_max;
} sts_server_config;

typedef struct {
	int enabled;
	int cache_expires_in;
	char *cookie_name;
	int accept_token_in;
	apr_hash_t *accept_token_in_options;
	char *resource;
} sts_dir_config;

void *sts_create_server_config(apr_pool_t *pool, server_rec *svr);
void *sts_create_dir_config(apr_pool_t *pool, char *path);

apr_byte_t sts_util_http_token_exchange(request_rec *r, const char *token,
		const char *basic_auth, int ssl_validate_server, char **response);

int sts_cache_shm_post_config(server_rec *s);
int sts_cache_shm_child_init(apr_pool_t *p, server_rec *s);
apr_byte_t sts_cache_shm_get(request_rec *r, const char *section,
		const char *key, char **value);
apr_byte_t sts_cache_shm_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry);
int sts_cache_shm_destroy(server_rec *s);

apr_byte_t sts_util_read_form_encoded_params(request_rec *r, apr_table_t *table,
		char *data);
char *sts_util_get_cookie(request_rec *r, const char *cookieName);
apr_byte_t sts_util_http_call(request_rec *r, const char *url, const char *data,
		const char *content_type, const char *basic_auth,
		const char *soap_action, int ssl_validate_server, char **response,
		int timeout, const char *outgoing_proxy, const char *ssl_cert,
		const char *ssl_key);
apr_byte_t sts_util_http_post_form(request_rec *r, const char *url,
		const apr_table_t *params, const char *basic_auth,
		int ssl_validate_server, char **response, int timeout,
		const char *outgoing_proxy, const char *ssl_cert, const char *ssl_key);
char *sts_util_get_current_url(request_rec *r);
apr_byte_t sts_util_decode_json_and_check_error(request_rec *r, const char *str,
		json_t **json);
apr_byte_t sts_util_json_object_get_string(apr_pool_t *pool, json_t *json,
		const char *name, char **value, const char *default_value);

#endif /* MOD_STS_H_ */
