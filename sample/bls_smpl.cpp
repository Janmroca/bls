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

int sign(const std::string& m, const std::string& sKey, int id)
{
	log("signing message: " << m);
	bls::SecretKey sec;
	set(sKey, sec);

	bls::Signature s;
	sec.sign(s, m);
	std::cout << "sMsg: " << s << std::endl;
	std::cout << "signed by : " << sec << std::endl;

	return 0;
}

int verify(const std::string& m, const std::string& pKey, const std::string sMsg, int id)
{
	log("verify message " << m);
	bls::PublicKey pub;
	set(pKey, pub);

	bls::Signature s;
	set(sMsg, s);

	if (s.verify(pub, m)) {
		puts("verify ok");
		return 0;
	} else {
		puts("verify err");
		return 1;
	}
}

int share(size_t n, size_t k)
{
	log((int)k << "-out-of-" << (int)n << " threshold sharing");
	bls::SecretKey sec;
	//load(sec, secFile);

	bls::SecretKeyVec msk;
	sec.getMasterSecretKey(msk, k);

	bls::SecretKeyVec secVec(n);
	bls::IdVec ids(n);
	for (size_t i = 0; i < n; i++) {
		int id = i + 1;
		ids[i] = id;
		secVec[i].set(msk, id);
	}
	for (size_t i = 0; i < n; i++) {
		//save(secFile, secVec[i], ids[i]);
		bls::PublicKey pub;
		secVec[i].getPublicKey(pub);
		//save(pubFile, pub, ids[i]);
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
	size_t n;
	size_t k;
	int id;
	bls::IdVec ids;

	cybozu::Option opt;
	opt.appendParam(&mode, "init|sign|verify|share|recover");
	opt.appendOpt(&n, 10, "n", ": k-out-of-n threshold");
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
		if (msg.empty()) goto ERR_EXIT;
		if (sKey.empty()) goto ERR_EXIT;
		return sign(msg, sKey, id);
	} else if (mode == "verify") {
		if (msg.empty()) goto ERR_EXIT;
		if (pKey.empty()) goto ERR_EXIT;
		if (sMsg.empty()) goto ERR_EXIT;
		return verify(msg, pKey, sMsg, id);
	} else if (mode == "share") {
		return share(n, k);
	} else if (mode == "recover") {
		if (ids.empty()) {
			fprintf(stderr, "use -ids option. ex. share -ids 1 3 5\n");
			goto ERR_EXIT;
		}
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
