/*
 * orange-c-client.h Created on: Jun 12, 2019 Author: NullinV
 */

#ifndef ORANGE_C_CLIENT_H_
#define ORANGE_C_CLIENT_H_

#include <map>
#include <string>

#include <curl/curl.h>

#include <jansson.h>

#include <openssl/evp.h>

enum request_methods{GET,POST};

typedef std::map<std::string,std::string> str_map;
struct http_request{
	request_methods method;
	std::string request_target;
	str_map headers;
	std::string body;
};

struct http_response{
	int status_code;
	std::string reason_phrase;
	str_map headers;
	std::string body;
};

void client_init(const int argc, const char** argv, str_map &conf,SSL_CTX *&ctx, EVP_PKEY *&skey);
void client_clean(SSL_CTX * const ctx, EVP_PKEY * const skey);

std::string err_string();

std::string read_file(const std::string &filename);
std::string trim(const std::string &s);
std::string::size_type to_size_type(const std::string &str);

int post_doc(const std::string &json, int doc_type = 0);
int get_status(const std::string &doc_id, int doc_type = 0);
int perform(BIO * stream, const http_request &req, http_response &res);


int read_key(EVP_PKEY*& key, const std::string& keyfname, const std::string & pass_phrase = "",
		int key_type = 0 /*0 - private, 1 - public*/);
int sign(const std::string &msg, std::string & signature, EVP_PKEY* const pkey);
void base64_encode(const std::string & text, std::string & base64_text);
void base64_decode(const std::string & b64_str, std::string & d_str);

#endif /* ORANGE_C_CLIENT_H_ */
