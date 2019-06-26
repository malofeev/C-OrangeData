/*
 * orange-c-client.cpp Created on: Jun 3, 2019 Author: NullinV
 */
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "orange-c-client.h"

std::string escaped(const std::string& input) {
	std::string output;
	output.reserve(input.size());
	for (const char c : input) {
		switch (c) {
		case '\a':
			output += "\\a";
			break;
		case '\b':
			output += "\\b";
			break;
		case '\f':
			output += "\\f";
			break;
		case '\n':
			output += "\\n\n";
			break;
		case '\r':
			output += "\\r";
			break;
		case '\t':
			output += "\\t";
			break;
		case '\v':
			output += "\\v";
			break;
		default:
			output += c;
			break;
		}
	}

	return output;
}

void print_cn_name(const char* label, X509_NAME* const name) {
	int idx = -1, success = 0;
	unsigned char *utf8 = NULL;

	do {
		if (!name)
			break;

		idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
		if (!(idx > -1))
			break;

		X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
		if (!entry)
			break;

		ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
		if (!data)
			break;

		int length = ASN1_STRING_to_UTF8(&utf8, data);
		if (!utf8 || !(length > 0))
			break;

		std::cout << "  " << label << ": " << utf8 << std::endl;
		success = 1;

	} while (0);

	if (utf8)
		OPENSSL_free(utf8);

	if (!success)
		std::cout << "  " << label << ": <not available>" << std::endl;
	;
}

void print_san_name(const char* label, X509* const cert) {
	int success = 0;
	GENERAL_NAMES* names = NULL;
	unsigned char* utf8 = NULL;

	do {
		if (!cert)
			break;

		names = (GENERAL_NAMES*) X509_get_ext_d2i(cert, NID_subject_alt_name, 0,
				0);
		if (!names)
			break;

		int i = 0, count = sk_GENERAL_NAME_num(names);
		if (!count)
			break;

		for (i = 0; i < count; ++i) {
			GENERAL_NAME* entry = sk_GENERAL_NAME_value(names, i);
			if (!entry)
				continue;

			if (GEN_DNS == entry->type) {
				int len1 = 0, len2 = -1;

				len1 = ASN1_STRING_to_UTF8(&utf8, entry->d.dNSName);
				if (utf8) {
					len2 = (int) strlen((const char*) utf8);
				}

				if (len1 != len2) {
					std::cerr
							<< "  Strlen and ASN1_STRING size do not match (embedded null?): "
							<< len2 << " vs " << len1 << std::endl;
				}

				/* If there's a problem with string lengths, then     */
				/* we skip the candidate and move on to the next.     */
				/* Another policy would be to fails since it probably */
				/* indicates the client is under attack.              */
				if (utf8 && len1 && len2 && (len1 == len2)) {
					std::cout << "  " << label << ": " << utf8 << std::endl;
					success = 1;
				}

				if (utf8) {
					OPENSSL_free(utf8), utf8 = NULL;
				}
			} else {
				std::cerr << "Unknown GENERAL_NAME type: " << entry->type
						<< std::endl;
			}
		}

	} while (0);

	if (names)
		GENERAL_NAMES_free(names);

	if (utf8)
		OPENSSL_free(utf8);

	if (!success)
		std::cout << "  " << label << ": <not available>" << std::endl;
}
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {

	int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	int err = X509_STORE_CTX_get_error(x509_ctx);

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
	X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

	fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth,
			preverify);

	print_cn_name("Issuer (cn)", iname);

	print_cn_name("Subject (cn)", sname);

	if (depth == 0) {
		print_san_name("Subject (san)", cert);
	}

	if (preverify == 0) {
		if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
			std::cout
					<< "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
					<< std::endl;
		else if (err == X509_V_ERR_CERT_UNTRUSTED)
			std::cout << "  Error = X509_V_ERR_CERT_UNTRUSTED" << std::endl;
		else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
			std::cout << "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN"
					<< std::endl;
		else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
			std::cout << "  Error = X509_V_ERR_CERT_NOT_YET_VALID" << std::endl;
		else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
			std::cout << "  Error = X509_V_ERR_CERT_HAS_EXPIRED" << std::endl;
		else if (err == X509_V_OK)
			std::cout << "  Error = X509_V_OK" << std::endl;
		else
			std::cout << "  Error = " << err << std::endl;
	}
	return 1;
}

void client_init(int argc, char** argv, str_map &conf, SSL_CTX *&ctx,
		EVP_PKEY *&skey) {
	int ret = 1;
	char * w_pass_phrase = NULL;

	do {

		if (argc < 2) {
			std::cout << "Usage: orange-c-client\n file - configuration\n";
			break;
		}

		std::string line;
		std::ifstream cfg_file(argv[1]);
		if (!cfg_file.is_open()) {
			std::cout << "Failed to open configuration file :" << argv[1]
					<< std::endl;
			break;
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

		if (!conf.count("url")) {
			std::cout << "Configuration file doesn't have url line"
					<< std::endl;
			exit(1);
		}

		if (!conf.count("inn")) {
			std::cout << "Configuration file doesn't have inn line"
					<< std::endl;
			exit(1);
		}

		if (conf.count("signkey")) {
			if (!read_key(skey, conf["signkey"])) {
				std::cout << "Failed to read signkey file" << std::endl;
				break;
			}
		} else {
			std::cout << "Configuration file doesn't have signkey line"
					<< std::endl;
			break;
		};

		SSL_library_init();
		SSL_load_error_strings();
		;

		const SSL_METHOD* method = TLS_method();

		if (!(NULL != method)) {
			std::cerr << err_string("TLS_method");
			break;
		}

		ctx = SSL_CTX_new(method);

		if (!(ctx != NULL)) {
			std::cerr << err_string("SSL_CTX_new");
			break;
		}

		if (conf.count("pass_phrase")) {
			w_pass_phrase = new char[conf["pass_phrase"].length() + 1];
			std::strcpy(w_pass_phrase, conf["pass_phrase"].c_str());
			SSL_CTX_set_default_passwd_cb_userdata(ctx, w_pass_phrase);
		}

		if (conf.count("key")) {
			if (SSL_CTX_use_RSAPrivateKey_file(ctx, conf["key"].c_str(),
			SSL_FILETYPE_PEM) != 1) {
				std::cerr << err_string("SSL_CTX_use_RSAPrivateKey_file");
				break;
			}
		} else {
			std::cout << "Configuration file doesn't have key line"
					<< std::endl;
			break;
		}

		if (conf.count("certificate")) {
			if (SSL_CTX_use_certificate_file(ctx, conf["certificate"].c_str(),
			SSL_FILETYPE_PEM) != 1) {
				std::cerr << err_string("SSL_CTX_use_certificate_file");
				break;
			}
		} else {
			std::cout << "Configuration file doesn't have certificate line"
					<< std::endl;
			break;
		}

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
		SSL_CTX_set_verify_depth(ctx, 5);

		SSL_CTX_set_options(ctx,
		SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

		if (conf.count("verify_locations"))
			if (SSL_CTX_load_verify_locations(ctx, NULL,
					conf["verify_locations"].c_str()) != 1) {
				std::cerr << err_string("SSL_CTX_load_verify_locations");
				break;
			}
		ret = 0;
	} while (0);

	if (w_pass_phrase)
		delete[] w_pass_phrase;

	if (!!ret)
		exit(1);
}

void client_clean(SSL_CTX *&ctx, EVP_PKEY *&skey) {
	if (NULL != ctx)
		SSL_CTX_free(ctx);
	if (NULL != skey)
		EVP_PKEY_free(skey);
}

int connect(SSL_CTX * const ctx, BIO*&web, const std::string &url) {
	int ret = 0;
	SSL *ssl = NULL;
	std::string host = get_host(url);
	std::string port = get_port(url);

	do {
		web = BIO_new_ssl_connect(ctx);
		if (!(web != NULL)) {
			std::cerr << err_string("BIO_new_ssl_connect");
			break;
		}

		if (BIO_set_conn_hostname(web, (host+port).c_str()) != 1) {
			std::cerr << err_string("BIO_set_conn_hostname");
			break;
		}

		BIO_get_ssl(web, &ssl);

		if (!(ssl != NULL)) {
			std::cerr << err_string("BIO_get_ssl");
			break;
		}

		if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1) {
			std::cerr << err_string("SSL_set_cipher_list");
			break;
		}

		if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
			std::cerr << err_string("SSL_set_tlsext_host_name");
			break;
		}

		if (BIO_do_connect(web) != 1) {
			std::cerr << err_string("BIO_do_connect");
			break;
		}

		if (BIO_do_handshake(web) != 1) {
			std::cerr << err_string("BIO_do_handshake");
			break;
		}

		X509* cert = SSL_get_peer_certificate(ssl);
		if (cert) {
			X509_free(cert);
		} else {
			std::cerr
					<< err_string(
							"SSL_get_peer_certificate : X509_V_ERR_APPLICATION_VERIFICATION");
			break;
		}

		if (SSL_get_verify_result(ssl) != X509_V_OK) {
			std::cerr << err_string("SSL_get_verify_result(ssl)");
			break;
		}

		ret = 1;
	} while (0);
	return !!ret;
}

int parse_http_message(const std::string &mes, http_response &res) {
	int ret = 0;

	std::istringstream in(mes);
	std::string line;
	do {
		{
			std::getline(in, line);
			std::istringstream iss(line);
			std::vector<std::string> tokens {
					std::istream_iterator<std::string> { iss },
					std::istream_iterator<std::string> { } };
			if (tokens.size() != 3) {
				std::cout << "Bad Status line:" << line << std::endl;
				break;
			}

			try {
				res.status_code = std::stoi(tokens[1]);
			} catch (std::invalid_argument &ex) {
				std::cout << "Bad Status line:" << line << std::endl;
				break;
			} catch (std::out_of_range &ex) {

				std::cout << "Bad Status line:" << line << std::endl;
				break;
			};

			res.reason_phrase = tokens[2];
		}

		std::getline(in, line);
		while (line != "\r") {
			auto pos = line.find(':');
			if (pos != std::string::npos)
				res.headers[trim(line.substr(0, pos))] = trim(
						line.substr(pos + 1, line.size()));
			else {
				std::cout << "Bad header line:" << line << std::endl;
				break;
			}
			std::getline(in, line);
		}
		if (line != "\r")
			break;

//chunked body
		//content-type body
		ret = 1;
	} while (0);
	return !!ret;
}

int perform(SSL_CTX * const ctx, http_request &req, http_response &res) {
	int ret = 0;
	BIO *web = NULL, *out = NULL;
	BUF_MEM *bufferPtr;
	std::string req_str, res_str;

	do {
		if (connect(ctx, web, req.headers["Host"]) != 1)
			break;

		req_str += method_str(req.method) + ' ' + req.request_target;
		if (req.query.size() > 0) {
			req_str += '?';
			for (auto it : req.query)
				req_str += it.first + '=' + it.second + '&';
			req_str.erase(req_str.end());
		}
		req_str += " HTTP/1.1\r\n";

		if (req.headers.count("Connection") == 0)
			req.headers["Connection"] = "close";

		for (auto it : req.headers)
			req_str += it.first + ": " + it.second + "\r\n";

		req_str += "\r\n";

		if (req.method == POST)
			req_str += req.body;

		std::string::size_type len = BIO_puts(web, req_str.c_str());
		ERR_get_error();
		if (len != req_str.length()) {
			std::cerr << err_string("BIO_puts");
			std::cerr << "Put  " << len << "b from " << req_str.length() << "b"
					<< std::endl;
			break;
		}

		len = 0;
		out = BIO_new(BIO_s_mem());

		do {
			char buff[1536] = { };
			len = BIO_read(web, buff, sizeof(buff));
			if (len < 0)
				std::cerr << err_string("BIO_read");
			if (len > 0)
				BIO_write(out, buff, len);
		} while (len > 0 || BIO_should_retry(web));

		BIO_flush(out);
		BIO_get_mem_ptr(out, &bufferPtr);

		if ((*bufferPtr).length > 0)
			res_str.assign((*bufferPtr).data, (*bufferPtr).length);
		else
			break;

		if (parse_http_message(res_str, res))
			ret = 1;
	} while (0);

	std::cout << "req start:\n" << escaped(req_str) << "req fin\n";
	std::cout << "res start:\n" << escaped(res_str) << "res fin\n";

	if (out != NULL)
		BIO_free_all(out);

	if (web != NULL)
		BIO_free_all(web);
	return !!ret;
}

int post_doc(str_map &conf, SSL_CTX * const ctx, const EVP_PKEY * const skey,
		const std::string &json, int type) {

	int ret = 0;
////The headers included in the linked list must not be CRLF-terminated, because libcurl adds CRLF after each header item.
//	struct curl_slist *headers = NULL;
//	CURLcode res;
//	EVP_PKEY* key = NULL;
//	std::string signature;
//	std::string b64_sign;
//
//	free(buf->memory);
//	buf->memory = NULL;
//	buf->size = 0;
//
//	read_key(key, conf["signkey"]);
//
//	sign(body, signature, key);
//	base64_encode(signature, b64_sign);
//
//	headers = curl_slist_append(headers, ("X-Signature: " + b64_sign).c_str());
//
//	std::string clh("Content-Length: ");
//	clh.append(std::to_string(body.length()));
//	headers = curl_slist_append(headers, clh.c_str());
//
//	headers = curl_slist_append(headers,
//			"Content-Type: application/json; charset=utf-8");
//	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//
//	curl_easy_setopt(curl, CURLOPT_POST, 1L);
//	curl_easy_setopt(curl, CURLOPT_URL, conf["url"].c_str());
//
//	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
//	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
//
//	res = curl_easy_perform(curl);
//	if (res != CURLE_OK) {
//		fprintf(stderr, "curl_easy_perform() POST failed: %s\n",
//				curl_easy_strerror(res));
//	}
//	get_info(curl, buf);
	return ret;
}

int get_status(str_map &conf, SSL_CTX *ctx, const std::string &doc_id,
		std::string &json, int type) {
	http_request req;
	http_response res;
	int ret = 0;

	req.method = GET;
	req.request_target = get_target(conf["url"])
			+ (type == 0 ? "/documents/" : "/corrections/") + conf["inn"]
			+ "/status/" + doc_id;
	req.headers["Host"] = get_host(conf["url"]) + get_port(conf["url"]);

	if (perform(ctx, req, res) && res.status_code == 200) {
		json = res.body;
		ret = 1;
	};

	return ret;
}

int read_key(EVP_PKEY*& pkey, const std::string &keyfname,
		const std::string &pass_phrase,
		int key_type /*0 - private, 1 - public*/) {
	int result = 0;

	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	RSA *rsa = NULL;
	char *w_pass_phrase = NULL;

	do {
		pkey = EVP_PKEY_new();
		if (pkey == NULL) {
			std::cout << "EVP_PKEY_new failed (1)," << err_string();
			break;
		}

		FILE *key_file = fopen(keyfname.c_str(), "r");
		if (key_file == NULL) {
			std::cout << "EVP_PKEY_new failed (1)," << err_string();
			break;
		}

		int rc;

		if (pass_phrase != "") {
			w_pass_phrase = new char[pass_phrase.length() + 1];
			strcpy(w_pass_phrase, pass_phrase.c_str());
		}
		if (key_type) {
			rsa = PEM_read_RSA_PUBKEY(key_file, &rsa, NULL, w_pass_phrase);
			fclose(key_file);
			if (rsa == NULL) {
				std::cout << "PEM_read_RSAPublicKey failed, " << err_string();
				break;
			}
			rc = EVP_PKEY_assign_RSA(pkey, RSAPublicKey_dup(rsa));
		} else {
			rsa = PEM_read_RSAPrivateKey(key_file, &rsa, NULL, w_pass_phrase);
			fclose(key_file);
			if (rsa == NULL) {
				std::cout << "PEM_read_RSAPrivateKey failed, " << err_string();
				break;
			}
			rc = EVP_PKEY_assign_RSA(pkey, RSAPrivateKey_dup(rsa));
		}

		if (rc != 1) {
			std::cout << "EVP_PKEY_assign_RSA failed, " << err_string();
			break;
		}
		result = 1;

	} while (0);

	if (rsa) {
		RSA_free(rsa);
		rsa = NULL;
	}
	if (w_pass_phrase)
		delete[] w_pass_phrase;

	return !!result;
}

int sign(const std::string & msg, std::string & signature,
		EVP_PKEY * const pkey) {
	int result = -1;

	if (!pkey) {
		return -1;
	}

	unsigned char * signature_buff = NULL;
	size_t slen = 0;

	EVP_MD_CTX* ctx = NULL;

	do {
		ctx = EVP_MD_CTX_create();
		if (ctx == NULL) {
			std::cout << "EVP_MD_CTX_create failed, " << err_string();
			break;
		}

		const EVP_MD* md = EVP_get_digestbyname("SHA256");
		if (md == NULL) {
			std::cout << "EVP_get_digestbyname failed, " << err_string();
			break;
		}

		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		if (rc != 1) {
			std::cout << "EVP_DigestInit_ex failed, " << err_string();
			break;
		}

		rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
		if (rc != 1) {
			std::cout << "EVP_DigestSignInit failed, " << err_string();
			break;
		}

		rc = EVP_DigestSignUpdate(ctx, msg.c_str(), msg.length());
		if (rc != 1) {
			std::cout << "EVP_DigestSignUpdate failed, " << err_string();
			break;
		}

		size_t req = 0;
		rc = EVP_DigestSignFinal(ctx, NULL, &req);
		if (rc != 1) {
			std::cout << "EVP_DigestSignFinal failed (1), " << err_string();
			break;
		}

		if (!(req > 0)) {
			std::cout << "EVP_DigestSignFinal failed (2), " << err_string();
			break;
		}

		signature_buff = new unsigned char[req];
		if (signature_buff == NULL) {
			std::cout << "new failed, " << err_string();
			break;
		}

		slen = req;
		rc = EVP_DigestSignFinal(ctx, signature_buff, &slen);
		if (rc != 1) {
			std::cout << "EVP_DigestsignFinal failed (3), return code " << rc
					<< ", " << err_string();
			break;
		}

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

	/*
	 * BIO_f_base64() is a filter BIO that base64 encodes any data written through it and decodes any data read through it.
	 */
	b64 = BIO_new(BIO_f_base64());
	/*
	 * A memory BIO is a source/sink BIO which uses memory for its I/O.
	 * Data written to a memory BIO is stored in a BUF_MEM structure which is extended as appropriate to accommodate the stored data
	 */
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

std::string err_string(std::string label) {
	unsigned long err = ERR_get_error();
	const char* const str = ERR_reason_error_string(err);
	if (str)
		return str;
	else
		return label + " error 0x" + std::to_string(err) + "\t"
				+ ERR_error_string(err, NULL) + "\n";
}

std::string get_host(const std::string &url) {
	std::string::size_type scheme_pos = url.find("://");
	if (scheme_pos == std::string::npos)
		scheme_pos = -1;
	else
		scheme_pos += 2;
	std::string::size_type target = url.find('/', scheme_pos + 1); //check ""
	std::string::size_type port = url.find(':', scheme_pos + 1);

	return url.substr(scheme_pos + 1, std::min(port, target) - scheme_pos - 1);
}

std::string get_port(const std::string &url) {
	std::string::size_type scheme_pos = url.find("://");
	if (scheme_pos == std::string::npos)
		scheme_pos = -1;
	else
		scheme_pos += 2;
	std::string::size_type port = url.find(':', scheme_pos + 1);
	if (port == std::string::npos)
		return "";
	std::string::size_type target = url.find('/', scheme_pos + 1);
	if (target == std::string::npos)
		target = url.length();
	return url.substr(port, target - port);
}

std::string get_target(const std::string &url) {
	std::string::size_type scheme_pos = url.find("://");
	if (scheme_pos == std::string::npos)
		scheme_pos = -1;
	else
		scheme_pos += 2;
	std::string::size_type target = url.find('/', scheme_pos + 1);

	return target == std::string::npos ?
			"" :
			url.substr(target,
					url.length() - target
							- (url.at(url.length() - 1) == '/' ? 1 : 0));
}
std::string method_str(const request_methods m) {
	switch (m) {
	case POST:
		return "POST";
		break;
	case GET:
		return "GET";
		break;
	default:
		return "FALSE";
	}
}
