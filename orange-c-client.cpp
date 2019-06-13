/*
 * orange-c-client.cpp Created on: Jun 3, 2019 Author: NullinV
 */

#include <fstream>
#include <iostream>
#include <sstream>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "orange-c-client.h"

void client_init(int argc, char** argv,
		std::map<std::string, std::string> &conf, CURL *&curl,
		memory_struct * buf) {
	if (argc < 2) {
		std::cout << "Usage: orange-c-client\n file - configuration\n";
		exit(1);
	}

	std::string line;
	std::ifstream cfg_file(argv[1]);
	if (!cfg_file.is_open()) {
		std::cout << "Failed to open configuration file :" << argv[1]
				<< std::endl;
		exit(1);
	}
	std::cout << "Configuration file:" << argv[1] << std::endl;
	while (getline(cfg_file, line)) {
		auto pos = line.find('=');
		if (pos != std::string::npos)
			std::cout << line << std::endl;
		conf[trim(line.substr(0, pos))] = trim(
				line.substr(pos + 1, line.size()));
	}
	std::cout << std::endl;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_VERBOSE, std::stol(conf["debug"]));
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

		curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		curl_easy_setopt(curl, CURLOPT_SSLCERT, conf["certificate"].c_str());

		if (conf.count("pass_phrase"))
			curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
					conf["pass_phrase"].c_str());
		curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, conf["key"].c_str());

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void * )buf);
	} else {
		std::cout << "CURL initialization failed\n";
		exit(1);
	}
}

size_t write_memory_callback(void *contents, size_t size, size_t nmemb,
		void *userp) {
	size_t realsize = size * nmemb;
	struct memory_struct *mem = (struct memory_struct *) userp;

	char *ptr = (char*) realloc(mem->memory, mem->size + realsize + 1);
	if (!ptr) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize); //
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

void get_info(CURL *curl, const memory_struct *buf) {
	CURLcode res;

	do {
		long long_arg;
		char * ct = NULL;
		curl_off_t curl_off_t_arg;

		res = curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &long_arg);
		if (res != CURLE_OK)
			break;
		printf("The peer verification said %s\t", long_arg ? "Failed" : "Ok");

		res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &long_arg);
		if (res != CURLE_OK)
			break;
		printf("Response code: %ld\n", long_arg);

		res = curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &long_arg);
		if (res != CURLE_OK)
			break;
		printf("Request size: %ld bytes\t", long_arg);

		res = curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &curl_off_t_arg);
		if (res != CURLE_OK)
			break;
		printf("Uploaded: %" CURL_FORMAT_CURL_OFF_T " bytes\n", curl_off_t_arg);

		res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
		if (res != CURLE_OK)
			break;
		if (ct)
			printf("Content-Type: %s\n", ct);

	} while (0);
	if (res != CURLE_OK)
		fprintf(stderr, "curl_easy_getinfo() failed: %s\n",
				curl_easy_strerror(res));
	if (buf && buf->memory)
		printf("Body: \n%s\n", buf->memory);
	printf("\n");
}

CURLcode post(CURL * curl, const std::string &body,
		std::map<std::string, std::string> &conf, memory_struct *buf) {

	//The headers included in the linked list must not be CRLF-terminated, because libcurl adds CRLF after each header item.
	struct curl_slist *headers = NULL;
	CURLcode res;
	EVP_PKEY* key = NULL;
	std::string signature;
	std::string b64_sign;

	free(buf->memory);
	buf->memory = NULL;
	buf->size = 0;

	read_key(&key, conf["signkey"].c_str(), NULL);

	sign(body, signature, key);
	base64_encode(signature, b64_sign);

	headers = curl_slist_append(headers, ("X-Signature: " + b64_sign).c_str());

	std::string clh("Content-Length: ");
	clh.append(std::to_string(body.length()));
	headers = curl_slist_append(headers, clh.c_str());

	headers = curl_slist_append(headers,
			"Content-Type: application/json; charset=utf-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, conf["url"].c_str());

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() POST failed: %s\n",
				curl_easy_strerror(res));
	}
	get_info(curl, buf);
	return res;
}

CURLcode get(CURL * curl, const std::string &doc_id,
		std::map<std::string, std::string> &conf, memory_struct *buf) {
	struct curl_slist *headers = NULL;
	CURLcode res;

	free(buf->memory);
	buf->memory = NULL;
	buf->size = 0;

	curl_easy_setopt(curl, CURLOPT_POST, 0L);

	curl_easy_setopt(curl, CURLOPT_URL,
			(conf["url"] + conf["inn"] + "/status/" + doc_id).c_str());
	headers = curl_slist_append(headers,
			"Content-Type: application/json; charset=utf-8");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() GET failed: %s\n",
				curl_easy_strerror(res));
	}
	get_info(curl, buf);
	return res;
}

int read_key(EVP_PKEY** pkey, const char * keyfname,
		const std::string *pass_phrase,
		int key_type /*0 - private, 1 - public*/) {
	int result = -1;

	if (!pkey)
		return -1;

	if (*pkey != NULL) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
	}

	RSA *rsa = NULL;
	char *w_pass_phrase = NULL;

	do {
		*pkey = EVP_PKEY_new();
		assert(*pkey != NULL);
		if (*pkey == NULL) {
			std::cout << "EVP_PKEY_new failed (1)," << err_string();
			break;
		}

		FILE *key_file = fopen(keyfname, "r");
		assert(key_file != NULL);
		if (key_file == NULL) {
			std::cout << "EVP_PKEY_new failed (1)," << err_string();
			break;
		}

		int rc;

		if (pass_phrase) {
			w_pass_phrase = new char[(*pass_phrase).length() + 1];
			strcpy(w_pass_phrase, (*pass_phrase).c_str());
		}
		if (key_type) {
			rsa = PEM_read_RSA_PUBKEY(key_file, &rsa, NULL, w_pass_phrase);
			fclose(key_file);
			assert(rsa != NULL);
			if (rsa == NULL) {
				std::cout << "PEM_read_RSAPublicKey failed, " << err_string();
				break;
			}
			rc = EVP_PKEY_assign_RSA(*pkey, RSAPublicKey_dup(rsa));
		} else {
			rsa = PEM_read_RSAPrivateKey(key_file, &rsa, NULL, w_pass_phrase);
			fclose(key_file);
			assert(rsa != NULL);
			if (rsa == NULL) {
				std::cout << "PEM_read_RSAPrivateKey failed, " << err_string();
				break;
			}
			rc = EVP_PKEY_assign_RSA(*pkey, RSAPrivateKey_dup(rsa));
		}

		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_PKEY_assign_RSA failed, " << err_string();
			break;
		}
		result = 0;

	} while (0);

	if (rsa) {
		RSA_free(rsa);
		rsa = NULL;
	}
	if (w_pass_phrase)
		delete[] w_pass_phrase;

	return !!result;
}

int sign(const std::string & msg, std::string & signature, EVP_PKEY * pkey) {
	int result = -1;

	if (!pkey) {
		assert(0);
		return -1;
	}

	unsigned char * signature_buff = NULL;
	size_t slen = 0;

	EVP_MD_CTX* ctx = NULL;

	do {
		ctx = EVP_MD_CTX_create();
		assert(ctx != NULL);
		if (ctx == NULL) {
			std::cout << "EVP_MD_CTX_create failed, " << err_string();
			break;
		}

		const EVP_MD* md = EVP_get_digestbyname("SHA256");
		assert(md != NULL);
		if (md == NULL) {
			std::cout << "EVP_get_digestbyname failed, " << err_string();
			break;
		}

		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_DigestInit_ex failed, " << err_string();
			break;
		}

		rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_DigestSignInit failed, " << err_string();
			break;
		}

		rc = EVP_DigestSignUpdate(ctx, msg.c_str(), msg.length());
		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_DigestSignUpdate failed, " << err_string();
			break;
		}

		size_t req = 0;
		rc = EVP_DigestSignFinal(ctx, NULL, &req);
		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_DigestSignFinal failed (1), " << err_string();
			break;
		}

		assert(req > 0);
		if (!(req > 0)) {
			std::cout << "EVP_DigestSignFinal failed (2), " << err_string();
			break;
		}

		signature_buff = new unsigned char[req];
		assert(signature_buff != NULL);
		if (signature_buff == NULL) {
			std::cout << "new failed, " << err_string();
			break;
		}

		slen = req;
		rc = EVP_DigestSignFinal(ctx, signature_buff, &slen);
		assert(rc == 1);
		if (rc != 1) {
			std::cout << "EVP_DigestsignFinal failed (3), return code " << rc
					<< ", " << err_string();
			break;
		}

		assert(req == slen);
		if (rc != 1) {
			std::cout
					<< "EVP_DigestsignFinal failed, mismatched signature sizes "
					<< req << ", " << slen;
			break;
		}

		signature.assign(reinterpret_cast<char*>(signature_buff), slen);
		delete[] signature_buff;
		result = 0;

	} while (0);

	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	return !!result;
}

void base64_encode(const std::string &text, std::string &base64_text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Don't add '\n' by BIO_f_base64 according to https://tools.ietf.org/html/rfc2045#section-6.8

	BIO_write(bio, text.c_str(), text.length());
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	base64_text.assign((*bufferPtr).data, (*bufferPtr).length);/*https://bugzilla.redhat.com/show_bug.cgi?id=1691853 fixed in openssl-1.1.1b-5.fc29 openssl-1.1.1b-5.fc30*/
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
}

void base64_decode(const std::string & b64_str, std::string & d_str) {
	BIO *bio, *b64;

	std::string::size_type b64_len = b64_str.length(), d_len = (b64_len * 3)
			/ 4;
	if (b64_str[b64_len - 2] == '=')
		d_len -= 2;
	else if (b64_str[b64_len - 1] == '=')
		d_len -= 1;

	char*d_buff = new char[d_len];
	char*b64_buff = new char[b64_len + 1];
	strcpy(b64_buff, b64_str.c_str());

	bio = BIO_new_mem_buf(b64_buff, b64_len);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	std::string::size_type length = BIO_read(bio, d_buff, b64_len);
	BIO_free_all(bio);
	if (length != d_len)
		std::cout << err_string();
	d_str.assign(d_buff, d_len);
	delete[] b64_buff;
	delete[] d_buff;
}

std::string::size_type to_size_type(const std::string &str) {
	std::stringstream ss(str);
	std::string::size_type res;
	ss >> res;
	return res;
}

std::string err_string() {
	unsigned long err = ERR_get_error();
	return "error 0x" + std::to_string(err) + "\t" + ERR_error_string(err, NULL)
			+ "\n";
}

std::string read_file(const std::string &filename) {

	std::ifstream ifs(filename, std::ios::binary);

	std::stringstream sstr;
	sstr << ifs.rdbuf();
	return sstr.str();
}

std::string trim(const std::string &s) {
	auto start = s.begin();
	while (start != s.end() && std::isspace(*start)) {
		start++;
	}

	auto end = s.end();
	do {
		end--;
	} while (std::distance(start, end) > 0 && std::isspace(*end));

	return std::string(start, end + 1);
}
