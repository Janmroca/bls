#define MCLBN_FP_UNIT_SIZE 4
#include <bls/bls.hpp>
#include <cybozu/option.hpp>
#include <cybozu/itoa.hpp>
#include <sstream>

#define log(x) std::cout << "Log: " << x << std::endl;

template<class T>
void set(const std::string& in, T& t)
{
	std::istringstream iss(in);
	if (!(iss >> t)) throw cybozu::Exception("can't set") << in;
}

int init()
{
	log("Initializing bls.");
	bls::SecretKey sec;
	sec.init();
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

int recover(const bls::IdVec& ids)
{
	printf("recover from");
	for (size_t i = 0; i < ids.size(); i++) {
		std::cout << ' ' << ids[i];
	}
	printf("\n");

	bls::SignatureVec sigVec(ids.size());
	for (size_t i = 0; i < sigVec.size(); i++) {
		//load(sigVec[i], signFile, ids[i]);
	}

	bls::Signature s;
	s.recover(sigVec, ids);
	//save(signFile, s);

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

	cybozu::Option opt;
	opt.appendParam(&mode, "init|sign|verify|share|recover");
	opt.appendOpt(&k, 3, "k", ": k-out-of-n threshold");
	opt.appendOpt(&sKey, "", "sk", ": secret key");
	opt.appendOpt(&pKey, "", "pk", ": public key");
	opt.appendOpt(&msg, "", "m", ": message to be signed");
	opt.appendOpt(&sMsg, "", "sm", ": signed message");
	opt.appendOpt(&id, 0, "id", ": id of secretKey");
	opt.appendVec(&ids, "ids", ": select k id in [0, n). this option should be last");
	opt.appendHelp("h");
	if (!opt.parse(argc, argv)) {
		goto ERR_EXIT;
	}

	if (mode == "init") {
		return init();
	} else if (mode == "sign") {
		if (sKey.empty()) goto ERR_EXIT;
		if (msg.empty()) goto ERR_EXIT;
		return sign(sKey, msg);
	} else if (mode == "verify") {
		if (pKey.empty()) goto ERR_EXIT;
		if (msg.empty()) goto ERR_EXIT;
		if (sMsg.empty()) goto ERR_EXIT;
		return verify(pKey, msg, sMsg);
	} else if (mode == "share") {
		if (sKey.empty()) goto ERR_EXIT;
		if (!k) goto ERR_EXIT;
		if (ids.empty()) goto ERR_EXIT;
		return share(sKey, k, ids);
	} else if (mode == "recover") {
		if (ids.empty()) goto ERR_EXIT;
		return recover(ids);
	} else {
		fprintf(stderr, "bad mode %s\n", mode.c_str());
	}
ERR_EXIT:
	opt.usage();
	return 1;
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}
