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
	std::cout << "\tinit" << std::endl;
	std::cout << "\tinit -id <id>" << std::endl;
	std::cout << "\tsign -m <msg> -sk <sk>" << std::endl;
	std::cout << "\tverify -m <msg> -sm <sigmsg> -pk <pk>" << std::endl;
	std::cout << "\tshare -sk <sk> -k <k> -ids <id1> <id2>..." << std::endl;
	std::cout << "\trecover -sigs <sig1> <sig2>... -ids <id1> <id2>..." << std::endl;
	std::cout << "\tgetpk -sk <sk>" << std::endl;
	std::cout << "\tsecshare -id <id> -keys <sk1> <sk2>..." << std::endl;
	std::cout << "\tpubshare -id <id> -keys <pk1> <pk2>..." << std::endl;
	std::cout << "\teqpks -keys <pk1> <pk2>" << std::endl;
	std::cout << "\taddsks -keys <sk1> <sk2>" << std::endl;
	std::cout << "\taddpks -keys <pk1> <pk2>" << std::endl;
	std::cout << "\texportpk -pk <pk>" << std::endl;
	std::cout << "\texportsk -sk <sk>" << std::endl;
	std::cout << "\texportsig -sig <sig>" << std::endl;

	return 1;
}

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

int init(const int id)
{
	log("Initializing bls with id.");
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

int genSecretKeyShare(const std::string& id, const std::vector<std::string>& keys)
{
	bls::Id bId;
	set(id, bId);
	int k = keys.size();
	int dataSize = sizeof(blsSecretKey);
	void* msk = malloc(dataSize * k);
	bls::SecretKey sk;

	for (int i = 0; i < k; ++i)
	{
		bls::SecretKey sKey;
		set(keys[i], sKey);
		memcpy(msk + dataSize * i, &sKey.self_, dataSize);
	}

	blsSecretKeyShare(&sk.self_, (blsSecretKey*)msk, k, &bId.self_);
	std::cout << "sk: " << sk << std::endl;
	return 0;
}

int genPublicKeyShare(const std::string& id, const std::vector<std::string>& keys)
{
	bls::Id bId;
	set(id, bId);
	int k = keys.size();
	int dataSize = sizeof(blsPublicKey);
	void* msk = malloc(dataSize * k);
	bls::PublicKey pk;

	for (int i = 0; i < k; ++i)
	{
		bls::PublicKey pKey;
		set(keys[i], pKey);
		memcpy(msk + dataSize * i, &pKey.self_, dataSize);
	}

	blsPublicKeyShare(&pk.self_, (blsPublicKey*)msk, k, &bId.self_);
	std::cout << "pk: " << pk << std::endl;
	return 0;
}

int publicKeyIsEqual(const std::string& pKey1, const std::string& pKey2)
{
	bls::PublicKey pk1, pk2;
	set(pKey1, pk1);
	set(pKey2, pk2);

	return pk1 == pk2;
}

int addSecretKeys(const std::string& sKey1, const std::string& sKey2)
{
	bls::SecretKey sk1, sk2;
	set(sKey1, sk1);
	set(sKey2, sk2);
	blsSecretKeyAdd(&sk1.self_, &sk2.self_);

	std::cout << "sk: " << sk1 << std::endl;
	return 0;
}

int addPublicKeys(const std::string& pKey1, const std::string& pKey2)
{
	bls::PublicKey pk1, pk2;
	set(pKey1, pk1);
	set(pKey2, pk2);
	blsPublicKeyAdd(&pk1.self_, &pk2.self_);

	std::cout << "pk: " << pk1 << std::endl;
	return 0;
}

int exportPublicKey(const std::string& pKey)
{
	bls::PublicKey pk;
	set(pKey, pk);
	int buffSize = 64;
	void* buff = malloc(buffSize);
	if (!blsPublicKeySerialize(buff, buffSize, &pk.self_)) return 1;

	std::cout << "pk: " << buff << std::endl;
	return 0;
}

int exportSecretKey(const std::string& sKey)
{
	bls::SecretKey sk;
	set(sKey, sk);
	int buffSize = 64;
	void* buff = malloc(buffSize);
	if (!blsSecretKeySerialize(buff, buffSize, &sk.self_)) return 1;

	std::cout << "sk: " << buff << std::endl;
	return 0;
}

int exportSignature(const std::string& sig)
{
	bls::Signature signature;
	set(sig, signature);
	int buffSize = 64;
	void* buff = malloc(buffSize);
	if (!blsSignatureSerialize(buff, buffSize, &signature.self_)) return 1;

	std::cout << "sig: " << buff << std::endl;
	return 0;
}

int main(int argc, char *argv[])
	try
{
	bls::init(); // use BN254

	std::string mode;
	std::string msg;
	std::string sig;
	std::string sMsg;
	std::string sKey;
	std::string sId;
	std::string pKey;
	size_t k;
	int id;
	bls::IdVec ids;
	std::vector<std::string> sigs;
	std::vector<std::string> keys;

	cybozu::Option opt;
	opt.appendParam(&mode, "init|sign|verify|share|recover|getpk|secshare|pubshare|eqpks|addsks|addpks|exportpk|exportsk|exportsig");
	opt.appendOpt(&k, 0, "k", ": k-out-of-n threshold");
	opt.appendOpt(&sKey, "", "sk", ": secret key");
	opt.appendOpt(&pKey, "", "pk", ": public key");
	opt.appendOpt(&msg, "", "m", ": message to be signed");
	opt.appendOpt(&sMsg, "", "sm", ": signed message");
	opt.appendOpt(&id, 0, "id", ": id to initialize bls");
	opt.appendOpt(&sId, "", "sid", ": secret id");
	opt.appendOpt(&sig, "", "sig", ": sig to export");
	opt.appendVec(&ids, "ids", ": ids of threshold participants");
	opt.appendVec(&sigs, "sigs", ": signatures to recover from");
	opt.appendVec(&keys, "keys", "keys to generate share");
	opt.appendHelp("h");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}

	if (mode == "init") {
		if (!id) return init();
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
	} else if (mode == "secshare") {
		if (sId.empty()) return usage("Id is not set");
		if (!keys.size()) return usage("Secret keys are not set");
		return genSecretKeyShare(sId, keys);
	} else if (mode == "pubshare") {
		if (sId.empty()) return usage("Id is not set");
		if (!keys.size()) return usage("Public keys are not set");
		return genPublicKeyShare(sId, keys);
	} else if (mode == "eqpks") {
		if (keys.size() != 2) return usage("You must set exactly two public keys");
		return !publicKeyIsEqual(keys[0], keys[1]);
	} else if (mode == "addsks") {
		if (keys.size() != 2) return usage("You must set exactly two secret keys");
		return addSecretKeys(keys[0], keys[1]);
	} else if (mode == "addpks") {
		if (keys.size() != 2) return usage("You must set exactly two public keys");
		return addPublicKeys(keys[0], keys[1]);
	} else if (mode == "exportpk") {
		if (pKey.empty()) return usage("Public key is not set");
		return exportPublicKey(pKey);
	} else if (mode == "exportsk") {
		if (sKey.empty()) return usage("Secret key is not set");
		return exportSecretKey(sKey);
	} else if (mode == "exportsig") {
		if (sig.empty()) return usage("Sig is not set");
		return exportSignature(sig);
	} else {
		fprintf(stderr, "bad mode %s\n", mode.c_str());
	}
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}
