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

	json_t *content, *positions, *line, *checkClose,*payments,*p_line,*request, *response;
	json_error_t * j_error = NULL;
	std::string ofdName, processedAt;

	client_init(argc, argv, conf, curl, &buf);

	doc_id = std::to_string(std::time(0));

	post(curl, "", conf, &buf);//Error array example

	request = json_pack("{ssssss}","Id",doc_id.c_str(), "INN", conf["inn"].c_str(), "key",
			conf["inn"].c_str());

	content = json_pack("{siss}", "Type", 1,"CustomerContact","Dummy customer contact");

	positions = json_array();
	line = json_pack("{sfsfsiss}", "Quantity", 1.0, "Price", 1.0, "Tax", 6,
			"Text", "Dummy text");
	json_array_append_new(positions, line);
	json_object_set_new(content, "Positions", positions);

	checkClose = json_pack("{si}", "TaxationSystem", 1);
	payments = 	json_array();
	p_line = json_pack("{sisf}", "Type", 3, "Amount", 1.0);
	json_array_append_new(payments,p_line);
	json_object_set_new(checkClose,"Payments",payments);
	json_object_set_new(content, "CheckClose", checkClose);

	json_object_set_new(request, "Content", content);

	std::string body = json_dumps(request, JSON_COMPACT);

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
						response = json_loads(buf.memory, 0, j_error);
						ofdName = json_string_value(
								json_object_get(response, "ofdName"));
						processedAt = json_string_value(
								json_object_get(response, "processedAt"));
						std::cout << "Document processed by " << ofdName
								<< " at " << processedAt << std::endl;
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

