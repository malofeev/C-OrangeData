/** \file
 * C integration for OrangeData service header
 * orange-c-example.cpp Created on: Jun 12, 2019 \author NullinV
 */
#include <cstring>
#include <ctime>
#include <iostream>

#include "orange-c-client.h"

int main(int argc, char ** argv) {

	SSL_CTX* ctx = NULL;
	EVP_PKEY * skey = NULL;

	int ret = -1;
	std::string doc_id, rstr;

	str_map conf;

	json_t *content, *positions, *line, *checkClose, *payments, *p_line,
			*request;

	std::string ofdName, processedAt;

	client_init(argc, argv, conf, ctx, skey);

	doc_id = std::to_string(std::time(0));

	request = json_pack("{ssss}", "Id", doc_id.c_str(), "INN",
			conf["inn"].c_str());

	if (conf.count("group"))
		json_object_set_new(request, "group",
				json_string(conf["group"].c_str()));
	if (conf.count("key_name"))
		json_object_set_new(request, "key",
				json_string(conf["key_name"].c_str()));
	else
		json_object_set_new(request, "key", json_string(conf["inn"].c_str()));

	content = json_pack("{siss}", "Type", 1, "CustomerContact",
			"Dummy customer contact");

	positions = json_array();
	line = json_pack("{sfsfsiss}", "Quantity", 1.0, "Price", 1.0, "Tax", 6,
			"Text", "Dummy text");
	json_array_append_new(positions, line);
	json_object_set_new(content, "Positions", positions);

	checkClose = json_pack("{si}", "TaxationSystem", 1);
	payments = json_array();
	p_line = json_pack("{sisf}", "Type", 3, "Amount", 1.0);
	json_array_append_new(payments, p_line);
	json_object_set_new(checkClose, "Payments", payments);
	json_object_set_new(content, "CheckClose", checkClose);

	json_object_set_new(request, "Content", content);

	std::string body = json_dumps(request, JSON_COMPACT);

	std::string::size_type max_msg_len = to_size_type(conf["max_msg_len"]);
	if (body.length() > max_msg_len) {
		std::cout << "Max message length " << max_msg_len << " is exceeded\n";
	}
	post_doc(conf, ctx, skey, ""); //Error array example
	if (post_doc(conf, ctx, skey, body) == 201)
		ret = !get_status(conf, ctx, doc_id, rstr);

	client_clean(ctx, skey);

	return !!ret;

}

