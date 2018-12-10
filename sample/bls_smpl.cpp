#define MCLBN_FP_UNIT_SIZE 4
#include <bls/bls.hpp>
#include <cybozu/option.hpp>
#include <cybozu/itoa.hpp>
#include <sstream>

#define log(x) std::cout << "Log: " << x << std::endl;

int usage(const std::string& info)
{
	std::cout << "Input error: " << info << std::endl;
	std::cout << "Correct options are:" << std::endl;
	std::cout << "\tinit -id <id>" << std::endl;
	std::cout << "\tsign -m <msg> -sk <sk>" << std::endl;
	std::cout << "\tverify -m <msg> -sm <sigmsg> -pk <pk>" << std::endl;
	std::cout << "\tshare -sk <sk> -k <k> -ids <id1> <id2>..." << std::endl;
	std::cout << "\trecover -sigs <sig1> <sig2>... -ids <id1> <id2>..." << std::endl;
	std::cout << "\tgetpk -sk <sk>" << std::endl;

	return 1;
}

template<class T>
void set(const std::string& in, T& t)
{
	std::istringstream iss(in);
	if (!(iss >> t)) throw cybozu::Exception("can't set") << in;
}

int init(const int id)
{
	log("Initializing bls.");
	bls::SecretKey sec;
	sec.setHashOf(&id, sizeof(id));
	std::cout << "secKey: " << sec << std::endl;

	bls::PublicKey pub;
	sec.getPublicKey(pub);
	std::cout << "pubKey: " << pub << std::endl;

	return 0;
}

int sign(const std::string& sKey, const std::string& msg)
{
	log("signing message: " << msg);
	bls::SecretKey sec;
	set(sKey, sec);

	bls::Signature s;
	sec.sign(s, msg);
	std::cout << "sMsg: " << s << std::endl;

	return 0;
}

int verify(const std::string& pKey, const std::string& msg, const std::string sMsg)
{
	log("verify message " << msg);
	bls::PublicKey pub;
	set(pKey, pub);

	bls::Signature s;
	set(sMsg, s);

	if (s.verify(pub, msg)) {
		log("verify ok");
		return 0;
	} else {
		log("verify err");
		return 1;
	}
}

int share(const std::string& sKey, size_t k, const bls::IdVec& ids)
{
	size_t n = ids.size();
	log((int)k << "-out-of-" << (int)n << " threshold sharing");
	bls::SecretKey sec;
	set(sKey, sec);

	bls::SecretKeyVec msk;
	sec.getMasterSecretKey(msk, k);

	bls::SecretKeyVec secVec(n);
	for (size_t i = 0; i < n; i++)
		secVec[i].set(msk, ids[i]);

	for (size_t i = 0; i < n; i++) {
		bls::PublicKey pub;
		secVec[i].getPublicKey(pub);
		std::cout << "share-" << ids[i] << ": sk=" << secVec[i] << " pk=" << pub << std::endl;
	}

	return 0;
}

int recover(const bls::IdVec& ids, const std::vector<std::string>& sigs)
{
	log("recovering with " << sigs.size() << " signatures");

	bls::SignatureVec sigVec(sigs.size());
	for (size_t i = 0; i < sigVec.size(); i++) {
		set(sigs[i], sigVec[i]);
	}

	bls::Signature s;
	s.recover(sigVec, ids);
	std::cout << "recovered: " << s << std::endl;

	return 0;
}

int get_PubKey(const std::string& sKey)
{
	bls::SecretKey sec;
	set(sKey, sec);

	bls::PublicKey pub;
	sec.getPublicKey(pub);
	std::cout << "pk: " << pub << std::endl;

	return 0;	
}

int main(int argc, char *argv[])
	try
{
	bls::init(); // use BN254

	std::string mode;
	std::string msg;
	std::string sMsg;
	std::string sKey;
	std::string pKey;
	size_t k;
	int id;
	bls::IdVec ids;
	std::vector<std::string> sigs;

	cybozu::Option opt;
	opt.appendParam(&mode, "init|sign|verify|share|recover|getpk");
	opt.appendOpt(&k, 0, "k", ": k-out-of-n threshold");
	opt.appendOpt(&sKey, "", "sk", ": secret key");
	opt.appendOpt(&pKey, "", "pk", ": public key");
	opt.appendOpt(&msg, "", "m", ": message to be signed");
	opt.appendOpt(&sMsg, "", "sm", ": signed message");
	opt.appendOpt(&id, 0, "id", ": id to initialize bls");
	opt.appendVec(&ids, "ids", ": ids of threshold participants");
	opt.appendVec(&sigs, "sigs", ": signatures to recover from");
	opt.appendHelp("h");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}

	if (mode == "init") {
		if (!id) return usage("Id is not set");
		return init(id);
	} else if (mode == "sign") {
		if (sKey.empty()) return usage("Secret key is not set");
		if (msg.empty()) return usage("Message is not set");
		return sign(sKey, msg);
	} else if (mode == "verify") {
		if (pKey.empty()) return usage("Public key is not set");
		if (msg.empty()) return usage("Message is not set");
		if (sMsg.empty()) return usage("Signed message is not set");
		return verify(pKey, msg, sMsg);
	} else if (mode == "share") {
		if (sKey.empty()) return usage("Secret key is not set");
		if (!k) return usage("K is not set");
		if (ids.empty()) return usage("Ids are not set");
		return share(sKey, k, ids);
	} else if (mode == "recover") {
		if (!sigs.size()) return usage("Sigs are not set");
		if (!ids.size()) return usage("Ids are not set");
		return recover(ids, sigs);
	} else if (mode == "getpk") {
		if (sKey.empty()) return usage("Secret key is not set");
		return get_PubKey(sKey);
	} else {
		fprintf(stderr, "bad mode %s\n", mode.c_str());
	}
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}
