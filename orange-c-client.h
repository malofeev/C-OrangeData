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

struct memory_struct {
	char *memory = NULL;
	size_t size = 0;
};

void client_init(int argc, char** argv, std::map<std::string,std::string> &conf,CURL*& curl, memory_struct *buf);

std::string err_string();
void get_info(CURL *curl, const memory_struct * buf = NULL);

std::string read_file(const std::string &filename);
std::string trim(const std::string &s);
std::string::size_type to_size_type(const std::string &str);

size_t write_memory_callback(void *contents, size_t size, size_t nmemb,
		void *userp);

CURLcode post(CURL * curl, const std::string &body,std::map<std::string,std::string> &conf, memory_struct *buf, const int type = 0);
CURLcode get(CURL * curl, const std::string &doc_id,std::map<std::string,std::string> &conf, memory_struct *buf, const int type = 0);

int read_key(EVP_PKEY*& key, const std::string& keyfname, const std::string & pass_phrase = "",
		int key_type = 0 /*0 - private, 1 - public*/);
int sign(const std::string &msg, std::string & signature, EVP_PKEY* const pkey);
void base64_encode(const std::string & text, std::string & base64_text);
void base64_decode(const std::string & b64_str, std::string & d_str);



#endif /* ORANGE_C_CLIENT_H_ */
