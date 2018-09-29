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

#include <httpd.h>

#include <apr_base64.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define STS_WSTRUST_ENDPOINT_DEFAULT        NULL
#define STS_WSTRUST_ENDPOINT_AUTH_DEFAULT   STS_ENDPOINT_AUTH_NONE
#define STS_WSTRUST_APPLIES_TO_DEFAULT      NULL
#define STS_WSTRUST_TOKEN_TYPE_DEFAULT     "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
#define STS_WSTRUST_VALUE_TYPE_DEFAULT      "urn:pingidentity.com:oauth2:grant_type:validate_bearer"

#define STS_WSTRUST_XML_SOAP_NS				"http://www.w3.org/2003/05/soap-envelope"
#define STS_WSTRUST_XML_WSTRUST_NS			"http://docs.oasis-open.org/ws-sx/ws-trust/200512"
#define STS_WSTRUST_XML_WSSE_NS				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
#define STS_WSTRUST_XML_WSU_NS				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
#define STS_WSTRUST_XML_WSA_NS				"http://www.w3.org/2005/08/addressing"
#define STS_WSTRUST_XML_WSP_NS				"http://schemas.xmlsoap.org/ws/2004/09/policy"

#define STS_WSTRUST_ACTION                  STS_WSTRUST_XML_WSTRUST_NS "/RST/Issue"
#define STS_WSTRUST_REQUEST_TYPE            STS_WSTRUST_XML_WSTRUST_NS "/Issue"
#define STS_WSTRUST_KEY_TYPE                STS_WSTRUST_XML_WSTRUST_NS "/SymmetricKey"

int sts_wstrust_config_check_vhost(apr_pool_t *pool, server_rec *s,
		sts_server_config *cfg) {
	if (cfg->wstrust_endpoint == NULL) {
		sts_serror(s, STSWSTrustEndpoint " must be set in WS-Trust mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cfg->wstrust_applies_to == NULL) {
		sts_serror(s, STSWSTrustAppliesTo " must be set in WS-Trust mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cfg->wstrust_token_type == NULL) {
		sts_serror(s, STSWSTrustTokenType " must be set in WS-Trust mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cfg->wstrust_value_type == NULL) {
		sts_serror(s, STSWSTrustValueType " must be set in WS-Trust mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

static const char * sts_wstrust_get_endpoint(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_endpoint == NULL)
		return STS_WSTRUST_ENDPOINT_DEFAULT;
	return cfg->wstrust_endpoint;
}

static int sts_wstrust_get_endpoint_auth(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_endpoint_auth == STS_CONFIG_POS_INT_UNSET)
		return STS_WSTRUST_ENDPOINT_AUTH_DEFAULT;
	return cfg->wstrust_endpoint_auth;
}

static const char * sts_wstrust_get_applies_to(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_applies_to == NULL)
		return STS_WSTRUST_APPLIES_TO_DEFAULT;
	return cfg->wstrust_applies_to;
}

static const char * sts_wstrust_get_token_type(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_token_type == NULL)
		return STS_WSTRUST_TOKEN_TYPE_DEFAULT;
	return cfg->wstrust_token_type;
}

static const char * sts_wstrust_get_value_type(request_rec *r) {
	sts_server_config *cfg = (sts_server_config *) ap_get_module_config(
			r->server->module_config, &sts_module);
	if (cfg->wstrust_value_type == NULL)
		return STS_WSTRUST_VALUE_TYPE_DEFAULT;
	return cfg->wstrust_value_type;
}

const char *ws_trust_soap_call_template =
		"<s:Envelope xmlns:s=\"" STS_WSTRUST_XML_SOAP_NS "\">"
		"  <s:Header>"
		"    <wsse:Security xmlns:wsse=\"" STS_WSTRUST_XML_WSSE_NS "\">"
		"      <wsu:Timestamp xmlns:wsu=\"" STS_WSTRUST_XML_WSU_NS "\" wsu:Id=\"%s\">"
		"        <wsu:Created>%s</wsu:Created>"
		"        <wsu:Expires>%s</wsu:Expires>"
		"      </wsu:Timestamp>"
		"	     <wsse:BinarySecurityToken xmlns:wsu=\"" STS_WSTRUST_XML_WSU_NS "\" wsu:Id=\"%s\" ValueType=\"%s\">%s</wsse:BinarySecurityToken>"
		"    </wsse:Security>"
		"    <wsa:To xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">%s</wsa:To>"
		"    <wsa:Action xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">%s</wsa:Action>"
		"  </s:Header>"
		"  <s:Body><wst:RequestSecurityToken xmlns:wst=\"" STS_WSTRUST_XML_WSTRUST_NS "\">"
		"    <wst:TokenType>%s</wst:TokenType>"
		"    <wst:RequestType>%s</wst:RequestType>"
		"    <wsp:AppliesTo xmlns:wsp=\"" STS_WSTRUST_XML_WSP_NS "\">"
		"      <wsa:EndpointReference xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">"
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
			(const xmlChar *) STS_WSTRUST_XML_SOAP_NS) != 0) {
		fprintf(stderr, "Error: unable to register NS");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "wst",
			(const xmlChar *) STS_WSTRUST_XML_WSTRUST_NS) != 0) {
		fprintf(stderr, "Error: unable to register NS");
		xmlXPathFreeContext(xpathCtx);
		xmlFreeDoc(doc);
		return (-1);
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *) "wsse",
			(const xmlChar *) STS_WSTRUST_XML_WSSE_NS) != 0) {
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

static const char *sts_wstrust_xpath_expr_template = "/s:Envelope"
		"/s:Body"
		"/wst:RequestSecurityTokenResponseCollection"
		"/wst:RequestSecurityTokenResponse"
		"/wst:RequestedSecurityToken"
		"/wsse:BinarySecurityToken[@ValueType='%s']";

apr_byte_t sts_wstrust_exec(request_rec *r, sts_server_config *cfg,
		const char *token, char **rtoken) {

	char *response = NULL;
	const char *basic_auth = NULL;
	const char *client_cert = NULL;
	const char *client_key = NULL;
	char *data = NULL;
	const char *id1 = "_0";
	char created[STR_SIZE];
	char expires[STR_SIZE];
	const char *id2 = "Me";
	int enc_len = 0;
	char *b64 = NULL;
	apr_time_t now = apr_time_now();
	apr_time_t then = now + apr_time_from_sec(300);
	apr_size_t size;
	apr_time_exp_t exp;
	int auth;
	const xmlChar *xpath_expr = NULL;

	sts_debug(r, "enter");

	enc_len = apr_base64_encode_len(strlen(token));
	b64 = apr_palloc(r->pool, enc_len);
	apr_base64_encode(b64, (const char *) token, strlen(token));

	apr_time_exp_gmt(&exp, now);
	apr_strftime(created, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	apr_time_exp_gmt(&exp, then);
	apr_strftime(expires, &size, STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &exp);

	data = apr_psprintf(r->pool, ws_trust_soap_call_template, id1, created,
			expires, id2, sts_wstrust_get_value_type(r), b64,
			sts_wstrust_get_endpoint(r), STS_WSTRUST_ACTION,
			sts_wstrust_get_token_type(r),
			STS_WSTRUST_REQUEST_TYPE, sts_wstrust_get_applies_to(r),
			STS_WSTRUST_KEY_TYPE);

	auth = sts_wstrust_get_endpoint_auth(r);

	if (auth != STS_ENDPOINT_AUTH_NONE) {

		if (auth == STS_ENDPOINT_AUTH_BASIC) {

			const char *username = sts_get_config_method_option(r,
					cfg->wstrust_endpoint_auth_options,
					STS_ENDPOINT_AUTH_BASIC_STR,
					STS_ENDPOINT_AUTH_OPTION_USERNAME,
					NULL);
			const char *password = sts_get_config_method_option(r,
					cfg->wstrust_endpoint_auth_options,
					STS_ENDPOINT_AUTH_BASIC_STR,
					STS_ENDPOINT_AUTH_OPTION_PASSWORD,
					NULL);
			if (username == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_BASIC_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_USERNAME "\" option must be set on the configuration directive");
				return FALSE;
			}
			if (password == NULL) {
				sts_error(r,
						"when using \"" STS_ENDPOINT_AUTH_BASIC_STR "\" the \"" STS_ENDPOINT_AUTH_OPTION_PASSWORD "\" option must be set on the configuration directive");
				return FALSE;
			}
			basic_auth = apr_psprintf(r->pool, "%s:%s", username, password);

		} else if (auth == STS_ENDPOINT_AUTH_CLIENT_CERT) {

			if (sts_get_endpoint_auth_cert_key(r,
					cfg->wstrust_endpoint_auth_options, &client_cert,
					&client_key) == FALSE)
				return FALSE;

		}
	}

	if (sts_util_http_call(r, sts_wstrust_get_endpoint(r), data,
			STS_CONTENT_TYPE_SOAP_UTF8, basic_auth, sts_wstrust_get_endpoint(r),
			sts_get_ssl_validation(r), &response, sts_get_http_timeout(r),
			NULL, client_cert, client_key) == FALSE) {
		sts_error(r, "sts_util_http_call failed!");
		return FALSE;
	}

	xmlInitParser();

	xpath_expr = (const xmlChar *) apr_psprintf(r->pool,
			sts_wstrust_xpath_expr_template, sts_wstrust_get_token_type(r));

	if (sts_execute_xpath_expression(r, response, xpath_expr, rtoken) < 0) {
		sts_error(r, "sts_execute_xpath_expression failed!");
		return FALSE;
	}

	sts_warn(r, "returned token=%s", *rtoken);

	xmlCleanupParser();

	return TRUE;
}
