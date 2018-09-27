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

#include <http_core.h>
#include <http_protocol.h>
#include <curl/curl.h>

static char *sts_util_unescape_string(apr_pool_t *pool, const char *str) {
	CURL *curl = curl_easy_init();
	if (curl == NULL)
		return NULL;
	int counter = 0;
	char *replaced = (char *) str;
	while (str[counter] != '\0') {
		if (str[counter] == '+') {
			replaced[counter] = ' ';
		}
		counter++;
	}
	char *result = curl_easy_unescape(curl, replaced, 0, 0);
	if (result == NULL)
		return NULL;
	char *rv = apr_pstrdup(pool, result);
	curl_free(result);
	curl_easy_cleanup(curl);
	return rv;
}

apr_byte_t sts_util_read_form_encoded_params(apr_pool_t *pool,
		apr_table_t *table, char *data) {
	const char *key, *val, *p = data;

	while (p && *p && (val = ap_getword(pool, &p, '&'))) {
		key = ap_getword(pool, &val, '=');
		key = sts_util_unescape_string(pool, key);
		val = sts_util_unescape_string(pool, val);
		apr_table_set(table, key, val);
	}

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

typedef struct sts_util_curl_buffer {
	request_rec *r;
	char *memory;
	size_t size;
} sts_util_curl_buffer;

#define STS_CURL_MAX_RESPONSE_SIZE 1024 * 1024

static size_t sts_util_curl_write(void *contents, size_t size, size_t nmemb,
		void *userp) {
	size_t realsize = size * nmemb;
	sts_util_curl_buffer *mem = (sts_util_curl_buffer *) userp;

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

apr_byte_t sts_util_http_call(request_rec *r, const char *url, const char *data,
		const char *content_type, const char *basic_auth,
		const char *soap_action, int ssl_validate_server, char **response,
		int timeout, const char *outgoing_proxy, const char *ssl_cert,
		const char *ssl_key) {
	char curlError[CURL_ERROR_SIZE];
	sts_util_curl_buffer curlBuffer;
	CURL *curl;
	struct curl_slist *h_list = NULL;

	/* do some logging about the inputs */
	sts_debug(r,
			"url=%s, data=%s, content_type=%s, basic_auth=%s, soap_action=%s, ssl_validate_server=%d, timeout=%d ssl_cert=%s, ssl_key=%s",
			url, data, content_type, basic_auth, soap_action,
			ssl_validate_server, timeout, ssl_cert, ssl_key);

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
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sts_util_curl_write);
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

typedef struct sts_util_http_encode_t {
	request_rec *r;
	char *encoded_params;
} sts_util_http_encode_t;

static int sts_util_http_add_form_url_encoded_param(void* rec, const char* key,
		const char* value) {
	sts_util_http_encode_t *ctx = (sts_util_http_encode_t*) rec;
	sts_debug(ctx->r, "processing: %s=%s", key, value);
	const char *sep = ctx->encoded_params ? "&" : "";
	ctx->encoded_params = apr_psprintf(ctx->r->pool, "%s%s%s=%s",
			ctx->encoded_params ? ctx->encoded_params : "", sep,
					sts_util_escape_string(ctx->r, key),
					sts_util_escape_string(ctx->r, value));
	return 1;
}

char *sts_util_http_form_encoded_data(request_rec *r, const apr_table_t *params) {
	char *data = NULL;
	if ((params != NULL) && (apr_table_elts(params)->nelts > 0)) {
		sts_util_http_encode_t encode_data = { r, NULL };
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

static apr_byte_t sts_util_decode_json_object(request_rec *r, const char *str,
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

static char *sts_util_encode_json_object(request_rec *r, json_t *json,
		size_t flags) {
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

apr_byte_t sts_util_json_object_get_string(apr_pool_t *pool, json_t *json,
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

static const char *sts_util_hdr_in_get(const request_rec *r, const char *name) {
	const char *value = apr_table_get(r->headers_in, name);
	if (value)
		sts_debug(r, "%s=%s", name, value);
	return value;
}

static void sts_util_hdr_table_set(const request_rec *r, apr_table_t *table,
		const char *name, const char *value) {

	if (value != NULL) {

		char *s_value = apr_pstrdup(r->pool, value);

		/*
		 * sanitize the header value by replacing line feeds with spaces
		 * just like the Apache header input algorithms do for incoming headers
		 *
		 * this makes it impossible to have line feeds in values but that is
		 * compliant with RFC 7230 (and impossible for regular headers due to Apache's
		 * parsing of headers anyway) and fixes a security vulnerability on
		 * overwriting/setting outgoing headers when used in proxy mode
		 */
		char *p = NULL;
		while ((p = strchr(s_value, '\n')))
			*p = ' ';

		sts_debug(r, "%s: %s", name, s_value);
		apr_table_set(table, name, s_value);

	} else {

		sts_debug(r, "unset %s", name);
		apr_table_unset(table, name);

	}
}

void sts_util_hdr_in_set(const request_rec *r, const char *name,
		const char *value) {
	sts_util_hdr_table_set(r, r->headers_in, name, value);
}

static const char *sts_util_hdr_in_get_left_most_only(const request_rec *r,
		const char *name, const char *separator) {
	char *last = NULL;
	const char *value = sts_util_hdr_in_get(r, name);
	if (value)
		return apr_strtok(apr_pstrdup(r->pool, value), separator, &last);
	return NULL;
}

const char *sts_util_hdr_in_x_forwarded_proto_get(const request_rec *r) {
	return sts_util_hdr_in_get_left_most_only(r, STS_HEADER_X_FORWARDED_PROTO,
			",");
}

const char *sts_util_hdr_in_x_forwarded_host_get(const request_rec *r) {
	return sts_util_hdr_in_get_left_most_only(r, STS_HEADER_X_FORWARDED_HOST,
			",");
}

const char *sts_util_hdr_in_x_forwarded_port_get(const request_rec *r) {
	return sts_util_hdr_in_get_left_most_only(r, STS_HEADER_X_FORWARDED_PORT,
			",");
}

const char *sts_util_hdr_in_host_get(const request_rec *r) {
	return sts_util_hdr_in_get(r, STS_HEADER_HOST);
}

static const char *sts_util_get_current_url_scheme(const request_rec *r) {
	/* first see if there's a proxy/load-balancer in front of us */
	const char *scheme_str = sts_util_hdr_in_x_forwarded_proto_get(r);
	/* if not we'll determine the scheme used to connect to this server */
	if (scheme_str == NULL) {
#ifdef APACHE2_0
		scheme_str = (char *) ap_http_method(r);
#else
		scheme_str = (char *) ap_http_scheme(r);
#endif
	}
	if ((scheme_str == NULL)
			|| ((apr_strnatcmp(scheme_str, "http") != 0)
					&& (apr_strnatcmp(scheme_str, "https") != 0))) {
		sts_warn(r,
				"detected HTTP scheme \"%s\" is not \"http\" nor \"https\"; perhaps your reverse proxy passes a wrongly configured \"%s\" header: falling back to default \"https\"",
				scheme_str, STS_HEADER_X_FORWARDED_PROTO);
		scheme_str = "https";
	}
	return scheme_str;
}

static const char *sts_util_get_current_url_host(request_rec *r) {
	const char *host_str = sts_util_hdr_in_x_forwarded_host_get(r);
	if (host_str == NULL)
		host_str = sts_util_hdr_in_host_get(r);
	if (host_str) {
		host_str = apr_pstrdup(r->pool, host_str);
		char *p = strchr(host_str, ':');
		if (p != NULL)
			*p = '\0';
	} else {
		/* no Host header, HTTP 1.0 */
		host_str = ap_get_server_name(r);
	}
	return host_str;
}

static const char *sts_util_get_current_url_port(const request_rec *r,
		const char *scheme_str) {

	/*
	 * first see if there's a proxy/load-balancer in front of us
	 * that sets X-Forwarded-Port
	 */
	const char *port_str = sts_util_hdr_in_x_forwarded_port_get(r);
	if (port_str)
		return port_str;

	/*
	 * see if we can get the port from the "X-Forwarded-Host" header
	 * and if that header was set we'll assume defaults
	 */
	const char *host_hdr = sts_util_hdr_in_x_forwarded_host_get(r);
	if (host_hdr) {
		port_str = strchr(host_hdr, ':');
		if (port_str)
			port_str++;
		return port_str;
	}

	/*
	 * see if we can get the port from the "Host" header; if not
	 * we'll determine the port locally
	 */
	host_hdr = sts_util_hdr_in_host_get(r);
	if (host_hdr) {
		port_str = strchr(host_hdr, ';');
		if (port_str) {
			port_str++;
			return port_str;
		}
	}

	/*
	 * if X-Forwarded-Proto assume the default port otherwise the
	 * port should have been set in the X-Forwarded-Port header
	 */
	if (sts_util_hdr_in_x_forwarded_proto_get(r))
		return NULL;

	/*
	 * if no port was set in the Host header and no X-Forwarded-Proto was set, we'll
	 * determine the port locally and don't print it when it's the default for the protocol
	 */
	const apr_port_t port = r->connection->local_addr->port;
	if ((apr_strnatcmp(scheme_str, "https") == 0) && port == 443)
		return NULL;
	else if ((apr_strnatcmp(scheme_str, "http") == 0) && port == 80)
		return NULL;

	port_str = apr_psprintf(r->pool, "%u", port);
	return port_str;
}

static const char *sts_util_get_current_url_base(request_rec *r) {

	const char *scheme_str = sts_util_get_current_url_scheme(r);
	const char *host_str = sts_util_get_current_url_host(r);
	const char *port_str = sts_util_get_current_url_port(r, scheme_str);
	port_str = port_str ? apr_psprintf(r->pool, ":%s", port_str) : "";

	char *url = apr_pstrcat(r->pool, scheme_str, "://", host_str, port_str,
			NULL);

	return url;
}

char *sts_util_get_current_url(request_rec *r) {
	char *url = apr_pstrcat(r->pool, sts_util_get_current_url_base(r), r->uri,
			(r->args != NULL && *r->args != '\0' ? "?" : ""), r->args,
			NULL);
	sts_debug(r, "current URL: %s", url);
	return url;
}

char *sts_util_get_full_path(apr_pool_t *pool, const char *abs_or_rel_filename) {
	return (abs_or_rel_filename) ?
			ap_server_root_relative(pool, abs_or_rel_filename) : NULL;
}
