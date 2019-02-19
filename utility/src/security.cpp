#include <map>

#include <random>
#include "boost/crc.hpp"
#include "boost/lexical_cast.hpp"

#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/hmac.h"
#include "openssl/aes.h"
#include "openssl/des.h"

#include "escape_string.hpp"
#include "security.hpp"
#include "easyssl.hpp"
#include "bin_hex_iterator.hpp"

namespace crypto_util {

	typedef std::map<std::string, std::string> stringmap;

	thread_local static std::mt19937 mt = std::mt19937(std::random_device()());

	static bool base64_decode(const std::string &str, unsigned char *bytes, int &len)
	{
		const char* cstr = str.c_str();
		BIO* bmem = NULL;
		BIO* b64 = NULL;

		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new_mem_buf((void *)cstr, strlen(cstr));
		b64 = BIO_push(b64, bmem);
		len = BIO_read(b64, bytes, len);

		BIO_free_all(b64);
		return len > 0;
	}

	static std::string base64_decode(const std::string &str)
	{
		std::string out;
		out.resize(str.length());
		int out_len = out.length();
		if (base64_decode(str, (unsigned char*)out.data(), out_len))
			out.resize(out_len);
		else
			out.clear();
		return out;
	}

	static std::string base64_encode(const unsigned char *bytes, int len)
	{
		BIO* bmem = NULL;
		BIO* b64 = NULL;
		BUF_MEM* bptr = NULL;

		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new(BIO_s_mem());
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, bytes, len);
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);

		std::string str = std::string(bptr->data, bptr->length);
		BIO_free_all(b64);
		return str;
	}

	std::string base64_encode(std::string in)
	{
		return base64_encode((const unsigned char *)in.data(), in.size());
	}

	std::string rsa_sign(const std::string& content, const std::string& key, int type)
	{
		std::string signed_str;

		const char* key_cstr = key.c_str();
		int key_len = std::strlen(key_cstr);

		BIO* p_key_bio = BIO_new_mem_buf((void*)key_cstr, key_len);
		RSA* p_rsa = PEM_read_bio_RSAPrivateKey(p_key_bio, NULL, NULL, NULL);

		// 区别使用rsa1或rsa2方式来签名.
		if (p_rsa)
		{
			const char* cstr = content.c_str();
			int sha_len = SHA_DIGEST_LENGTH;
			std::vector<unsigned char> hash(sha_len, 0);
			int rsa_type = NID_sha1;
			int key_length = RSA_size(p_rsa);
			if (type == SHA1WithRSA)
			{
				SHA1((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == SHA256WithRSA)
			{
				rsa_type = NID_sha256;
				sha_len = SHA256_DIGEST_LENGTH;
				hash.resize(sha_len);
				SHA256((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == MD5WithRSA)
			{
				rsa_type = NID_md5;
				sha_len = MD5_DIGEST_LENGTH;
				hash.resize(sha_len);
				MD5((unsigned char*)(content.data()), content.length(), hash.data());
			}
			else
			{
				BOOST_ASSERT("error of sign type!" && false);
			}

			// 进行rsa签名.
			std::string sign;
			sign.resize(key_length);
			unsigned int sign_len = sign.size();
			int r = RSA_sign(rsa_type, hash.data(),
				sha_len, (unsigned char*)sign.data(), &sign_len, p_rsa);

			// 签名进行base64编码.
			if (r != 0 && sign.length() == sign_len)
			{
				sign.resize(sign_len);
				signed_str = base64_encode((unsigned char*)sign.data(), sign_len);
			}
		}

		RSA_free(p_rsa);
		BIO_free(p_key_bio);

		return signed_str;
	}

	std::string rsa_sign_raw(const std::string& content, const std::string& key, int type)
	{
		std::string signed_str;

		const char* key_cstr = key.c_str();
		int key_len = std::strlen(key_cstr);

		BIO* p_key_bio = BIO_new_mem_buf((void*)key_cstr, key_len);
		RSA* p_rsa = PEM_read_bio_RSAPrivateKey(p_key_bio, NULL, NULL, NULL);

		// 区别使用rsa1或rsa2方式来签名.
		if (p_rsa)
		{
			const char* cstr = content.c_str();
			int sha_len = SHA_DIGEST_LENGTH;
			std::vector<unsigned char> hash(sha_len, 0);
			int rsa_type = NID_sha1;
			int key_length = RSA_size(p_rsa);
			if (type == SHA1WithRSA)
			{
				SHA1((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == SHA256WithRSA)
			{
				rsa_type = NID_sha256;
				sha_len = SHA256_DIGEST_LENGTH;
				hash.resize(sha_len);
				SHA256((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == MD5WithRSA)
			{
				rsa_type = NID_md5;
				sha_len = MD5_DIGEST_LENGTH;
				hash.resize(sha_len);
				MD5((unsigned char*)(content.data()), content.length(), hash.data());
			}
			else
			{
				BOOST_ASSERT("error of sign type!" && false);
			}

			// 进行rsa签名.
			std::string sign;
			sign.resize(key_length);
			unsigned int sign_len = sign.size();
			int r = RSA_sign(rsa_type, hash.data(),
				sha_len, (unsigned char*)sign.data(), &sign_len, p_rsa);

			// 签名进行base64编码.
			if (r != 0 && sign.length() == sign_len)
			{
				return sign;
			}
			return "";
		}

		RSA_free(p_rsa);
		BIO_free(p_key_bio);

		return signed_str;
	}

	bool rsa_verify(const std::string& content,
		const std::string& sign, const std::string& key, int type)
	{
		bool result = false;

		const char* key_cstr = key.c_str();
		int key_len = strlen(key_cstr);

		BIO* p_key_bio = BIO_new_mem_buf((void *)key_cstr, key_len);
		RSA* p_rsa = PEM_read_bio_RSA_PUBKEY(p_key_bio, NULL, NULL, NULL);

		// 区别使用不同的类型rsa1或rsa2进行签名验证.
		if (p_rsa)
		{
			const char* cstr = content.c_str();
			int rsa_type = NID_sha1;
			int hash_len = SHA_DIGEST_LENGTH;
			std::vector<unsigned char> hash(hash_len, 0);

			// 根据类型进行不同的hash.
			if (type == SHA1WithRSA)
			{
				SHA1((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == SHA256WithRSA)
			{
				rsa_type = NID_sha256;
				hash_len = SHA256_DIGEST_LENGTH;
				hash.resize(hash_len);
				SHA256((unsigned char *)cstr, strlen(cstr), hash.data());
			}
			else if (type == MD5WithRSA)
			{
				rsa_type = NID_md5;
				hash_len = MD5_DIGEST_LENGTH;
				hash.resize(hash_len);
				MD5((unsigned char *)content.data(), content.size(), hash.data());
			}

			// base64解码签名字符串.
			int sign_len = RSA_size(p_rsa);
			std::vector<unsigned char> sign_cstr(sign_len, 0);
			if (base64_decode(sign, sign_cstr.data(), sign_len))
			{
				// 验证签名.
				int r = RSA_verify(rsa_type, hash.data(),
					hash_len, (unsigned char *)sign_cstr.data(), sign_len, p_rsa);
				if (r > 0)
					result = true;
			}
			else
			{
				result = false;
			}
		}

		RSA_free(p_rsa);
		BIO_free(p_key_bio);

		return result;
	}

	std::string rsa_pub_enc(const std::string& content, const std::string& key)
	{
		std::string signed_str;

		const char* key_cstr = key.c_str();
		int key_len = key.length();

		BIO* p_key_bio = BIO_new_mem_buf((void*)key_cstr, key_len);
		RSA* p_rsa = PEM_read_bio_RSA_PUBKEY(p_key_bio, NULL, NULL, NULL);

		// 区别使用rsa1或rsa2方式来签名.
		if (p_rsa)
		{
			std::string d = RSA_public_encrypt(p_rsa, content);

			// 签名进行base64编码.
			signed_str = base64_encode((unsigned char*)d.data(), d.length());
		}

		RSA_free(p_rsa);
		BIO_free(p_key_bio);

		return signed_str;
	}

	std::string rsa_priv_dec(const std::string& content, const std::string& key)
	{
		// 进行base64解码.

		auto raw_content = base64_decode(content);

		std::string signed_str;

		const char* key_cstr = key.c_str();
		int key_len = key.length();

		BIO* p_key_bio = BIO_new_mem_buf((void*)key_cstr, key_len);
		RSA* p_rsa = PEM_read_bio_RSAPrivateKey(p_key_bio, NULL, NULL, NULL);
		BIO_free(p_key_bio);

		std::unique_ptr<RSA, decltype(&RSA_free)> auto_rsa_release(p_rsa, &RSA_free);

		// 区别使用rsa1或rsa2方式来签名.
		if (p_rsa)
		{
			return RSA_private_decrypt(p_rsa, raw_content);
		}

		// RSA_free(p_rsa);

		return signed_str;
	}

	std::string hmac_md5_sign(const std::string& content, const std::string& key)
	{
		unsigned int result_len;
		unsigned char result[EVP_MAX_MD_SIZE];

		HMAC(EVP_md5(), key.c_str(), key.length(), (const unsigned char*)content.c_str(), content.length(), result, &result_len);

		std::string sign = boost::bin2hex(result, result + result_len);

		return sign;
	}

	std::string hmac_sha1_sign(const std::string& content, const std::string& key, encoding output_encoding)
	{
		unsigned int result_len;
		unsigned char result[EVP_MAX_MD_SIZE];

		HMAC(EVP_sha1(), key.c_str(), key.length(), (const unsigned char*)content.c_str(), content.length(), result, &result_len);

		if (output_encoding == encoding::base64)
		{
			return base64_encode(result, result_len);
		}
		else if (output_encoding == encoding::hex)
		{
			return boost::bin2hex(result, result + result_len);
		}
		else
		{
			BOOST_ASSERT_MSG(false, "Not Yet Implemented");
			return "";
		}
	}

	std::string hmac_sha512_sign(const std::string& content, const std::string& key)
	{
		unsigned int result_len = EVP_MAX_MD_SIZE;
		char result[EVP_MAX_MD_SIZE];

		HMAC(EVP_sha512(), key.c_str(), key.length(), (const unsigned char*)content.c_str(), content.length(), (unsigned char*)result, &result_len);

		return std::string(result, result_len);
	}

	std::string simple_num_hash(const std::string& content, int l)
	{
		static const char * encode_string[] = {
			"0",
			"1",
			"2",
			"3",
			"4",
			"5",
			"6",
			"7",
			"8",
			"9",
		};

		std::uniform_int_distribution<> num(0,9);

		boost::crc_32_type crc;

		crc.process_bytes(content.data(), content.size());

		std::string hash;

		hash  = boost::lexical_cast<std::string>(crc.checksum());

		while (hash.size() < (l - 2))
			hash = encode_string[num(mt)] + hash;

		return hash;
	}

	std::string aes_cbc_encrypt(std::string in, std::string key, std::string iv)
	{
		AES_KEY aes;
		if(AES_set_encrypt_key((unsigned char*)key.c_str(), key.size() * 8, &aes) < 0)
		{
			return "";
		}

		std::string out;

		out.resize(in.length() / 16 * 16 +  (in.length() %16 ? 16 : 0));

		AES_cbc_encrypt((unsigned char*)in.c_str(), (unsigned char*)(&out[0]), in.length(), &aes, (unsigned char*) iv.c_str(), AES_ENCRYPT);

		return base64_encode((unsigned char*)out.data(), out.length());
	}


	std::string aes_cbc_decrypt(std::string in, std::string key, std::string iv)
	{
		AES_KEY aes;
		if(AES_set_decrypt_key((unsigned char*)key.c_str(), key.size() * 8, &aes) < 0)
		{
			return "";
		}

		auto raw_in = base64_decode(in);

		std::string out;

		out.resize(raw_in.length() / 16 * 16 +  (raw_in.length() %16 ? 16 : 0));

		AES_cbc_encrypt((unsigned char*)raw_in.c_str(), (unsigned char*)(&out[0]), raw_in.length(), &aes, (unsigned char*) iv.c_str(), AES_DECRYPT);

		return out;
	}

	std::vector<unsigned char> aes_ecb_encrypt(std::vector<unsigned char> in, const AES_KEY& key)
	{
		std::vector<unsigned char> out;

		if (in.size() % 16 != 0)
		{
			int n_to_p = 16 - in.size() % 16;

			for (int i = 0; i < n_to_p; i++)
			{
				in.push_back(n_to_p);
			}

		}
		else
		{
			for (int i = 0; i < 16; i++)
				in.push_back(16);
		}

		out.resize(in.size());

		// in aligned to 16
		for (int i = 0; i < in.size(); i += 16)
		{
			AES_ecb_encrypt((unsigned char*)in.data() + i, (unsigned char*)(&out[0]) + i, &key, AES_ENCRYPT);
		}

		return out;
	}

	std::string aes_ecb_encrypt(std::string in, const AES_KEY& key)
	{
		std::string out;

		if (in.length() % 16 != 0)
		{
			int n_to_p = 16 - in.length() % 16;

			for (int i = 0; i < n_to_p; i++)
			{
				in.push_back(n_to_p);
			}

		}
		else
		{
			for (int i = 0; i < 16; i++)
				in.push_back(16);
		}

		out.resize(in.length());

		// in aligned to 16
		for (int i = 0; i < in.length(); i += 16)
		{
			AES_ecb_encrypt((unsigned char*)(&in[i]), (unsigned char*)(&out[i]), &key, AES_ENCRYPT);
		}

		return out;

	}

	std::string aes_ecb_encrypt(std::string in, std::string key, encoding output_encoding)
	{
		AES_KEY aes;
		if(AES_set_encrypt_key((unsigned char*)key.c_str(), key.size() * 8, &aes) < 0)
		{
			return "";
		}

		std::string out = aes_ecb_encrypt(in, aes);

		if (output_encoding == encoding::base64)
		{
			return base64_encode((unsigned char*)out.data(), out.length());
		}
		else if (output_encoding == encoding::hex)
		{
			return boost::bin2hex(std::begin(out), std::end(out));
		}
		return out;
	}

	std::vector<unsigned char> aes_ecb_decrypt(std::vector<unsigned char> raw_in, const AES_KEY& aes)
	{
		std::vector<unsigned char> out;
		std::size_t cipherlen = raw_in.size();
		out.resize(cipherlen);

		for (int i = 0; i < cipherlen; i += 16)
		{
			AES_ecb_encrypt((unsigned char*)raw_in.data() + i, (unsigned char*)(&out[0]) + i, &aes, AES_DECRYPT);
		}
		// remove padding
		std::size_t ps = (int)(out[cipherlen - 1]);
		out.resize(cipherlen - ps);

		return out;
	}

	std::string aes_ecb_decrypt(std::string raw_in, const AES_KEY& aes)
	{

		std::string out;
		std::size_t cipherlen = raw_in.length();
		out.resize(cipherlen);

		for (int i = 0; i < cipherlen; i += 16)
		{
			AES_ecb_encrypt((unsigned char*)raw_in.c_str() + i, (unsigned char*)(&out[0]) + i, &aes, AES_DECRYPT);
		}
		// remove padding
		std::size_t ps = (int)(out[cipherlen - 1]);
		out.resize(cipherlen - ps);

		return out;
	}

	std::string aes_ecb_decrypt(std::string in, std::string key, encoding input_encoding)
	{
		AES_KEY aes;
		if(AES_set_decrypt_key((unsigned char*)key.c_str(), key.size() * 8, &aes) < 0)
		{
			return "";
		}

		std::string raw_in;
		if (input_encoding == encoding::base64)
		{
			raw_in = base64_decode(in);
		}
		else if (input_encoding == encoding::hex)
		{
			raw_in = boost::hex2bin(in);
		}
		else
			raw_in = in;

		return aes_ecb_decrypt(raw_in, aes);
	}

	std::string encrypt_des_cbc(const std::string& data, const std::string& key, const std::string& iv)
	{
		auto cipher_type = EVP_get_cipherbyname("des-cbc");
		auto block_size = EVP_CIPHER_block_size(cipher_type);
		auto cleared_data = data;
		auto padding_size = block_size - cleared_data.size() % block_size;
		cleared_data.append(padding_size, static_cast<char>(padding_size));

		auto cipher_ctx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(cipher_ctx, cipher_type, nullptr, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str(), 1);
		EVP_CIPHER_CTX_set_padding(cipher_ctx, 1);

		std::string out;
		out.resize(cleared_data.size() + EVP_CIPHER_block_size(cipher_type));
		int length = 0;
		if (EVP_CipherUpdate(cipher_ctx, (unsigned char*)out.data(), &length, (unsigned char*)cleared_data.data(), cleared_data.size()))
		{
			out.resize(length);
		}
		else
		{
			out = "";
		}

		EVP_CIPHER_CTX_reset(cipher_ctx);
		EVP_CIPHER_CTX_free(cipher_ctx);

		return boost::bin2hex(out.data(), out.data() + out.size());
	}

	std::string decrypt_des_cbc(const std::string& data, const std::string& key, const std::string& iv)
	{
		auto encrypted_data = boost::hex2bin(data);

		auto cipher_type = EVP_get_cipherbyname("des-cbc");
		auto cipher_ctx = EVP_CIPHER_CTX_new();
		EVP_CipherInit_ex(cipher_ctx, cipher_type, nullptr, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str(), 0);

		std::string out;
		out.resize(encrypted_data.size() + EVP_CIPHER_block_size(cipher_type));
		int length = 0;
		if (EVP_CipherUpdate(cipher_ctx, (unsigned char*)out.data(), &length, (unsigned char*)encrypted_data.data(), out.size()))
		{
			if (length > 0)
			{
				length -= out[length - 1];
			}

			if (length > 0)
			{
				out.resize(length);
			}
			else
			{
				out = "";
			}
		}

		EVP_CIPHER_CTX_reset(cipher_ctx);
		EVP_CIPHER_CTX_free(cipher_ctx);

		return out;
	}

	std::string md5sum(const std::string& sign_data)
	{
		auto md5 = md5sum_raw(sign_data);

		std::string sign= boost::bin2hex(std::begin(md5), std::end(md5));

		return sign;
	}

	std::string md5sum_raw(const std::string& sign_data)
	{
		char md5sum[16] = {0};

// 		md5_sum_auto_dispatch((unsigned char*)(sign_data.data()), sign_data.length(), (unsigned char*)md5sum);
//
// 		std::string sign2(std::begin(md5sum), std::end(md5sum));
//
// 		return sign2;

		MD5((unsigned char*)(sign_data.data()), sign_data.length(), (unsigned char*)md5sum);

		std::string sign(std::begin(md5sum), std::end(md5sum));

		return sign;
	}

	std::string sha1_sum(const std::string& in)
	{
		unsigned char d[SHA_DIGEST_LENGTH];
		SHA1((const unsigned char*)in.data(), in.length(), d);
		std::string sign = boost::bin2hex(std::begin(d), std::end(d));
		return sign;
	}

	std::string sha256_sum(const std::string& in)
	{
		unsigned char d[SHA256_DIGEST_LENGTH];
		SHA256((const unsigned char*)in.data(), in.length(), d);
		std::string sign = boost::bin2hex(std::begin(d), std::end(d));
		return sign;
	}

	std::string sha1_sum_base32(const std::string& in)
	{
		unsigned char d[SHA_DIGEST_LENGTH];
		SHA1((const unsigned char*)in.data(), in.length(), d);

		return base32_encode<SHA_DIGEST_LENGTH>(d);
	}
}
