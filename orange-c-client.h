/*
 * orange-c-client.h Created on: Jun 12, 2019 Author: NullinV
 */

#ifndef ORANGE_C_CLIENT_H_
#define ORANGE_C_CLIENT_H_

#include <map>
#include <string>

#include <jansson.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

enum request_methods {
	GET, POST
};

std::string method_str(const request_methods m);


typedef std::map<std::string, std::string> str_map;
struct http_request {
	request_methods method;
	std::string request_target;
	str_map query;
	str_map headers;
	std::string body;
};

struct http_response {
	int status_code;
	std::string reason_phrase;
	str_map headers;
	std::string body;
};
const char* const PREFERRED_CIPHERS =
		"kEECDH:kEDH:kRSA:AESGCM:AES256:AES128:3DES:SHA256:SHA84:SHA1:!aNULL:!eNULL:!EXP:!LOW:!MEDIUM!ADH:!AECDH";

void client_init(int argc, char** argv, str_map &conf, SSL_CTX *&ctx,
		EVP_PKEY *&skey);
void client_clean(SSL_CTX *&ctx, EVP_PKEY *&skey);

std::string err_string(std::string label = "");

std::string read_file(const std::string &filename);
std::string trim(const std::string &s);
std::string::size_type to_size_type(const std::string &str);

std::string get_host(const std::string &url);
std::string get_port(const std::string &url);
std::string get_target(const std::string &url);

int read_chunked_body(std::istream &in,std::string &body);
int parse_http_message(const std::string &mes, http_response &res);

int connect(SSL_CTX * const ctx, BIO*&web, const std::string &url);
int perform(SSL_CTX * const ctx, http_request &req, http_response &res);

int post_doc(str_map &conf, SSL_CTX * const ctx, EVP_PKEY * const skey,
		const std::string &json, int type = 0);
int get_status(str_map &conf, SSL_CTX *ctx, const std::string &doc_id,
		std::string &json, int type = 0);

int read_key(EVP_PKEY*& key, const std::string& keyfname,
		const std::string & pass_phrase = "",
		int key_type = 0 /*0 - private, 1 - public*/);
int sign(const std::string &msg, std::string & signature, EVP_PKEY* const pkey);
void base64_encode(const std::string & text, std::string & base64_text);
void base64_decode(const std::string & b64_str, std::string & d_str);

#endif /* ORANGE_C_CLIENT_H_ */
