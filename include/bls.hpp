#pragma once
/**
	@file
	@brief BLS threshold signature on BN curve
	@author MITSUNARI Shigeo(@herumi)
	@license modified new BSD license
	http://opensource.org/licenses/BSD-3-Clause
*/
#include <vector>
#include <string>
#include <iosfwd>

namespace bls {

namespace impl {

struct PublicKey;
struct PrivateKey;
struct Sign;

} // bls::impl

/*
	BLS signature
	e : G2 x G1 -> Fp12
	Q in G2 ; fixed global parameter
	H : {str} -> G1
	s : private key
	sQ ; public key
	s H(m) ; signature of m
	verify ; e(sQ, H(m)) = e(Q, s H(m))
*/

/*
	initialize this library
	call this once before using the other method
*/
void init();

class Sign;
class PublicKey;
class PrivateKey;

typedef std::vector<Sign> SignVec;
typedef std::vector<PublicKey> PublicKeyVec;
typedef std::vector<PrivateKey> PrivateKeyVec;

/*
	[s_0, s_1, ..., s_{k-1}]
	s_0 is original private key
*/
typedef std::vector<PrivateKey> MasterPrivateKey;
/*
	[s_0 Q, ..., s_{k-1} Q]
	Q is global fixed parameter
*/
typedef std::vector<PublicKey> MasterPublicKey;

class Sign {
	impl::Sign *self_;
	int id_;
	friend class PublicKey;
	friend class PrivateKey;
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
public:
	Sign();
	~Sign();
	Sign(const Sign& rhs);
	Sign& operator=(const Sign& rhs);
	bool operator==(const Sign& rhs) const;
	bool operator!=(const Sign& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const Sign& s);
	friend std::istream& operator>>(std::istream& is, Sign& s);
	bool verify(const PublicKey& pub, const std::string& m) const;
	/*
		verify self(pop) with pub
	*/
	bool verify(const PublicKey& pub) const;
	/*
		recover sign from k signVec
	*/
	void recover(const std::vector<Sign>& signVec);
	/*
		add signature key only if id_ == 0
	*/
	void add(const Sign& rhs);
};

/*
	sQ ; public key
*/
class PublicKey {
	impl::PublicKey *self_;
	int id_;
	friend class PrivateKey;
	friend class Sign;
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
	template<class T, class G>
	friend struct Wrap;
public:
	PublicKey();
	~PublicKey();
	PublicKey(const PublicKey& rhs);
	PublicKey& operator=(const PublicKey& rhs);
	bool operator==(const PublicKey& rhs) const;
	bool operator!=(const PublicKey& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const PublicKey& pub);
	friend std::istream& operator>>(std::istream& is, PublicKey& pub);
	void getStr(std::string& str) const;
	/*
		set public for id from mpk
	*/
	void set(const MasterPublicKey& mpk, int id);
	/*
		recover publicKey from k pubVec
	*/
	void recover(const std::vector<PublicKey>& pubVec);
	/*
		add public key only if id_ == 0
	*/
	void add(const PublicKey& rhs);
};

/*
	s ; private key
*/
class PrivateKey {
	impl::PrivateKey *self_;
	int id_; // master if id_ = 0, shared if id_ > 0
	template<class G, class T>
	friend void LagrangeInterpolation(G& r, const T& vec);
	template<class T, class G>
	friend struct Wrap;
public:
	PrivateKey();
	~PrivateKey();
	PrivateKey(const PrivateKey& rhs);
	PrivateKey& operator=(const PrivateKey& rhs);
	bool operator==(const PrivateKey& rhs) const;
	bool operator!=(const PrivateKey& rhs) const { return !(*this == rhs); }
	int getId() const { return id_; }
	friend std::ostream& operator<<(std::ostream& os, const PrivateKey& prv);
	friend std::istream& operator>>(std::istream& is, PrivateKey& prv);
	/*
		make a private key for id = 0
	*/
	void init();
	void getPublicKey(PublicKey& pub) const;
	void sign(Sign& sign, const std::string& m) const;
	/*
		make Pop(Proof of Possesion)
	*/
	void getPop(Sign& pop, const PublicKey& pub) const;
	/*
		make [s_0, ..., s_{k-1}] to prepare k-out-of-n secret sharing
	*/
	void getMasterPrivateKey(MasterPrivateKey& msk, int k) const;
	/*
		set a private key for id > 0 from msk
	*/
	void set(const MasterPrivateKey& msk, int id);
	/*
		recover privateKey from k prvVec
	*/
	void recover(const std::vector<PrivateKey>& prvVec);
	/*
		add private key only if id_ == 0
	*/
	void add(const PrivateKey& rhs);
};

/*
	make master public key [s_0 Q, ..., s_{k-1} Q] from msk
*/
void getMasterPublicKey(MasterPublicKey& mpk, const MasterPrivateKey& msk);

/*
	make pop from msk and mpk
*/
void getPopVec(std::vector<Sign>& popVec, const MasterPrivateKey& msk, const MasterPublicKey& mpk);

inline Sign operator+(const Sign& a, const Sign& b) { Sign r(a); r.add(b); return r; }
inline PublicKey operator+(const PublicKey& a, const PublicKey& b) { PublicKey r(a); r.add(b); return r; }
inline PrivateKey operator+(const PrivateKey& a, const PrivateKey& b) { PrivateKey r(a); r.add(b); return r; }

} //bls
