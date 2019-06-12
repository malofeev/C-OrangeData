/*
 * orange-c-example.cpp Created on: Jun 12, 2019 Author: NullinV
 */
#include <chrono>
#include <ctime>
#include <iostream>
#include <thread>

#include "orange-c-client.h"

int main(int argc, char ** argv) {

	int ret = -1;
	long responce_code = -1;
	std::string doc_id;
	CURL *curl;

	std::map<std::string, std::string> conf;
	memory_struct buf;

	client_init(argc, argv, conf, curl, &buf);

	post(curl, "", conf, &buf);

	std::string body = read_file( { argv[2] });
	doc_id = std::to_string(std::time(0));
	body.replace(body.find("\"Id\":\"newId1\","), 14,
			"\"Id\":\"" + doc_id + "\",");

	std::string::size_type max_msg_len = to_size_type(conf["max_msg_len"]);
	if (body.length() > max_msg_len) {
		std::cout << "Max message length " << max_msg_len << " is exceeded\n";
	}

	if (post(curl, body, conf, &buf) == CURLE_OK) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responce_code);
		if (responce_code == 201) {
			long elapsed = 0;
			do {
				if (get(curl, doc_id, conf, &buf) == CURLE_OK) {
					curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
							&responce_code);
					if (responce_code == 200) {
						ret = 0;
						break;
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(1001));
				elapsed += 1001;
				if (elapsed > 180000)
					break;
			} while (1);
		}

	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return !!ret;

}

