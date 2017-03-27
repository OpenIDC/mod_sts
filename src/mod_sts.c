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
 * Copyright (C) 2017 ZmartZone IAM
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

//module AP_MODULE_DECLARE_DATA sts_module;

#define STS_CONFIG_POS_INT_UNSET -1
#define STS_CONFIG_DEFAULT_ENABLED 1

#define STS_CONFIG_DEFAULT_STS_URL      "https://localhost:9031/pf/sts.wst"
#define STS_CONFIG_DEFAULT_APPLIES_TO   "localhost:default:entityId"
#define STS_CONFIG_DEFAULT_TOKEN_TYPE   "urn:bogus:token"
//#define STS_CONFIG_DEFAULT_TOKEN_TYPE "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
#define STS_CONFIG_DEFAULT_COOKIE_NAME  "sts_cookie"

#define STS_CONFIG_DEFAULT_VALUE_TYPE   "urn:pingidentity.com:oauth2:grant_type:validate_bearer"
#define STS_CONFIG_DEFAULT_ACTION       "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
#define STS_CONFIG_DEFAULT_REQUEST_TYPE "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
#define STS_CONFIG_DEFAULT_KEY_TYPE     "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"

#define STS_CONFIG_DEFAULT_CACHE_SHM_SIZE 2048
#define STS_CONFIG_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 4096 + 512 + 17

#define STS_CONFIG_DEFAULT_CACHE_EXPIRES_IN 300

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

static const char * sts_get_sts_url(request_rec *r) {
	sts_server_config *c = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (c->sts_url == NULL)
		return STS_CONFIG_DEFAULT_STS_URL;
	return c->sts_url;
}

static const char * sts_get_applies_to(request_rec *r) {
	sts_server_config *c = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (c->applies_to == NULL)
		return STS_CONFIG_DEFAULT_APPLIES_TO;
	return c->applies_to;
}

static const char * sts_get_token_type(request_rec *r) {
	sts_server_config *c = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (c->token_type == NULL)
		return STS_CONFIG_DEFAULT_TOKEN_TYPE;
	return c->token_type;
}

static const char *sts_set_enabled(cmd_parms *cmd, void *m, const char *arg) {
	sts_dir_config *dir_cfg = (sts_dir_config *) m;
	if (strcmp(arg, "Off") == 0)
		dir_cfg->enabled = 0;
	if (strcmp(arg, "On") == 0)
		dir_cfg->enabled = 1;
	return "Invalid value: must be \"On\" or \"Off\"";
}

static int sts_get_enabled(request_rec *r) {
	sts_dir_config *dir_cfg = ap_get_module_config(r->per_dir_config,
			&sts_module);
	if (dir_cfg->enabled == STS_CONFIG_POS_INT_UNSET)
		return STS_CONFIG_DEFAULT_ENABLED;
	return dir_cfg->enabled;
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

static char *sts_get_access_token(request_rec *r) {
	sts_debug(r, "enter");
	char *access_token = NULL;
	const char *auth_line = apr_table_get(r->headers_in, "Authorization");
	if (auth_line) {
		sts_debug(r, "authorization header found");
		if (apr_strnatcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")
				== 0) {
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

#define STS_OIDC_ACCESS_TOKEN "OIDC_access_token"
#define STS_CACHE_SECTION     "sts"

static int sts_handler(request_rec *r) {
	sts_debug(r, "enter");

	if (sts_get_enabled(r) != 1) {
		sts_debug(r, "disabled");
		return DECLINED;
	}

	const char *access_token = NULL;

	access_token = apr_table_get(r->subprocess_env, STS_OIDC_ACCESS_TOKEN);
	if (access_token == NULL) {
		sts_debug(r,
				"no access_token found in subprocess environment variables");
		access_token = sts_get_access_token(r);
		if (access_token == NULL) {
			sts_debug(r,
					"no access_token found Authorization header: return DECLINED");
			return DECLINED;
		}
	}

	char *sts_token = NULL;
	sts_cache_shm_get(r, STS_CACHE_SECTION, access_token, &sts_token);

	if (sts_token == NULL) {
		sts_debug(r, "cache miss");
		if (sts_util_http_token_exchange(r, access_token, NULL, 0,
				&sts_token) == FALSE) {
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
			"url=%s, data=%s, content_type=%s, soap_action=%s, bearer_token=%s, ssl_validate_server=%d",
			url, data, content_type, basic_auth, soap_action,
			ssl_validate_server);

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
			(ssl_validate_server != FALSE ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			(ssl_validate_server != FALSE ? 2L : 0L));

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
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_auth_openidc");

	/* set optional outgoing proxy for the local network */
	if (outgoing_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, outgoing_proxy);
	}

	/* see if we need to add a soap action header */
	if (soap_action != NULL) {
		h_list = curl_slist_append(h_list,
				apr_psprintf(r->pool, "soapAction: %s", soap_action));
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
				apr_psprintf(r->pool, "Content-type: %s", content_type));
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

apr_byte_t sts_util_http_token_exchange(request_rec *r, const char *token,
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

	int timeout = 20;

	apr_time_t now = apr_time_now();
	apr_time_t then = now + apr_time_from_sec(300);
	apr_size_t size;
	apr_time_exp_t exp;

	apr_time_exp_gmt(&exp, now);
	apr_strftime(created, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	apr_time_exp_gmt(&exp, then);
	apr_strftime(expires, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	char *data = apr_psprintf(r->pool, ws_trust_soap_call_template, id1,
			created, expires, id2, STS_CONFIG_DEFAULT_VALUE_TYPE, b64,
			sts_get_sts_url(r), STS_CONFIG_DEFAULT_ACTION,
			sts_get_token_type(r),
			STS_CONFIG_DEFAULT_REQUEST_TYPE, sts_get_applies_to(r),
			STS_CONFIG_DEFAULT_KEY_TYPE);

	if (sts_util_http_call(r, sts_get_sts_url(r), data,
			"application/soap+xml; charset=utf-8", basic_auth,
			sts_get_sts_url(r), ssl_validate_server, &response, timeout, NULL,
			NULL, NULL) == FALSE) {
		sts_error(r, "sts_util_http_call failed!");
		return FALSE;
	}

	xmlInitParser();

	const xmlChar *xpath_expr = (const xmlChar *) apr_psprintf(r->pool,
			xpath_expr_template, sts_get_token_type(r));

	if (sts_execute_xpath_expression(r, response, xpath_expr, rtoken) < 0) {
		sts_error(r, "sts_execute_xpath_expression failed!");
		return FALSE;
	}

	sts_warn(r, "returned token=%s", *rtoken);

	xmlCleanupParser();

	return TRUE;
}

void *sts_create_server_config(apr_pool_t *pool, server_rec *svr) {
	sts_server_config *c = apr_pcalloc(pool, sizeof(sts_server_config));
	c->sts_url = NULL;
	c->applies_to = NULL;
	c->token_type = NULL;
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
	c->sts_url = add->sts_url != NULL ? add->sts_url : base->sts_url;
	c->applies_to =
			add->applies_to != NULL ? add->applies_to : base->applies_to;
	c->token_type =
			add->token_type != NULL ? add->token_type : base->token_type;
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
		AP_INIT_TAKE1(
				"STSEnabled",
				sts_set_enabled,
				NULL,
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Enable or disable mod_sts."),
		AP_INIT_TAKE1(
				"STSUrl",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, sts_url),
				RSRC_CONF,
				"Set the STS endpoint."),
		AP_INIT_TAKE1(
				"STSAppliesTo",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, applies_to),
				RSRC_CONF,
				"Set the AppliesTo value."),
		AP_INIT_TAKE1(
				"STSTokenType",
				sts_set_string_slot,
				(void*)APR_OFFSETOF(sts_server_config, token_type),
				RSRC_CONF,
				"Set the Token Type."),
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

