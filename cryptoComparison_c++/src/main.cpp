#include <sys/time.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cassert>
#include <string>
#include <cstring>
#include <cryptopp/des.h>
#include <cryptopp/rsa.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>
#include <cryptopp/dh.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

time_t getTime()
{
        struct timeval tp;
        gettimeofday(&tp, NULL);
        long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
        return (time_t)ms;
}

int DES_CBC(std::string& filePath, CryptoPP::SecByteBlock* keyPtr) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::DES::DEFAULT_KEYLENGTH);
    
    time_t t;
    // gen key
    if(keyPtr == NULL) {
      time_t t = getTime();
      prng.GenerateBlock(key, sizeof(key));
      t = getTime() - t;
      std::cout << "Genkey: " << t << std::endl;
    } else {
	key = *keyPtr;
    }

    // gen iv
    byte iv[CryptoPP::DES::BLOCKSIZE];
    t = getTime();
    prng.GenerateBlock(iv, sizeof(iv));
    t = getTime() - t;
    std::cout << "GenIV: " << t << std::endl;
    
    std::string ciphertext;
    std::string decryptedtext;

    try
    {
           // Create Cipher Text
           CryptoPP::DES::Encryption encryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
           CryptoPP::CBC_Mode_ExternalCipher::Encryption modeEncryption( encryption, iv );
           time_t encryptT = getTime();
           CryptoPP::FileSource fs1(filePath.c_str(), true, new CryptoPP::StreamTransformationFilter(modeEncryption, new CryptoPP::StringSink(ciphertext)));
	   encryptT = getTime() - encryptT;
 	   std::cout << "Encrypt: " << encryptT << std::endl;

	
	   // decrypt
    	   CryptoPP::DES::Decryption decryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
	   CryptoPP::CBC_Mode_ExternalCipher::Decryption modeDecryption(decryption, iv);
	   time_t decryptT = getTime();
	   CryptoPP::StreamTransformationFilter stfDecryptor(modeDecryption, new CryptoPP::StringSink(decryptedtext) );
	   stfDecryptor.Put( reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	   decryptT = getTime() - decryptT;
	   stfDecryptor.MessageEnd();
	   std::cout << "Decrypt: " << decryptT << std::endl;
    }
    catch( const CryptoPP::Exception& e )
    {
            std::cerr << e.what() << std::endl;
    }

    return 0;
}


int DES_OFB(std::string& filePath) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::DES::DEFAULT_KEYLENGTH);
    
    // gen key
    time_t t = getTime();
    prng.GenerateBlock(key, sizeof(key));
    t = getTime() - t;
    std::cout << "Genkey: " << t << std::endl;
    
    // gen iv
    byte iv[CryptoPP::DES::BLOCKSIZE];
    t = getTime();
    prng.GenerateBlock(iv, sizeof(iv));
    t = getTime() - t;
    std::cout << "GenIV: " << t << std::endl;
    
    std::string ciphertext;
    std::string decryptedtext;

    try
    {
           // Create Cipher Text
           CryptoPP::DES::Encryption encryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
           CryptoPP::OFB_Mode_ExternalCipher::Encryption modeEncryption( encryption, iv );
           time_t encryptT = getTime();
           CryptoPP::FileSource fs1(filePath.c_str(), true, new CryptoPP::StreamTransformationFilter(modeEncryption, new CryptoPP::StringSink(ciphertext)));
	   encryptT = getTime() - encryptT;
 	   std::cout << "Encrypt: " << encryptT << std::endl;

	
	   // decrypt
    	   CryptoPP::DES::Decryption decryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
	   CryptoPP::OFB_Mode_ExternalCipher::Decryption modeDecryption(decryption, iv);
	   time_t decryptT = getTime();
	   CryptoPP::StreamTransformationFilter stfDecryptor(modeDecryption, new CryptoPP::StringSink(decryptedtext) );
	   stfDecryptor.Put( reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	   decryptT = getTime() - decryptT;
	   stfDecryptor.MessageEnd();
	   std::cout << "Decrypt: " << decryptT << std::endl;
    }
    catch( const CryptoPP::Exception& e )
    {
            std::cerr << e.what() << std::endl;
    }

    return 0;
}

int AES_CBC(std::string& filePath) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    
    // gen key
    time_t t = getTime();
    prng.GenerateBlock(key, sizeof(key));
    t = getTime() - t;
    std::cout << "Genkey: " << t << std::endl;
    
    // gen iv
    byte iv[CryptoPP::AES::BLOCKSIZE];
    t = getTime();
    prng.GenerateBlock(iv, sizeof(iv));
    t = getTime() - t;
    std::cout << "GenIV: " << t << std::endl;
    
    std::string ciphertext;
    std::string decryptedtext;

    try
    {
           // Create Cipher Text
           CryptoPP::AES::Encryption encryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
           CryptoPP::CBC_Mode_ExternalCipher::Encryption modeEncryption( encryption, iv );
           time_t encryptT = getTime();
           CryptoPP::FileSource fs1(filePath.c_str(), true, new CryptoPP::StreamTransformationFilter(modeEncryption, new CryptoPP::StringSink(ciphertext)));
	   encryptT = getTime() - encryptT;
 	   std::cout << "Encrypt: " << encryptT << std::endl;

	
	   // decrypt
    	   CryptoPP::AES::Decryption decryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	   CryptoPP::CBC_Mode_ExternalCipher::Decryption modeDecryption(decryption, iv);
	   time_t decryptT = getTime();
	   CryptoPP::StreamTransformationFilter stfDecryptor(modeDecryption, new CryptoPP::StringSink(decryptedtext) );
	   stfDecryptor.Put( reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	   decryptT = getTime() - decryptT;
	   stfDecryptor.MessageEnd();
	   std::cout << "Decrypt: " << decryptT << std::endl;
    }
    catch( const CryptoPP::Exception& e )
    {
            std::cerr << e.what() << std::endl;
    }

    return 0;
}


int AES_OFB(std::string& filePath) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    
    // gen key
    time_t t = getTime();
    prng.GenerateBlock(key, sizeof(key));
    t = getTime() - t;
    std::cout << "Genkey: " << t << std::endl;
    
    // gen iv
    byte iv[CryptoPP::AES::BLOCKSIZE];
    t = getTime();
    prng.GenerateBlock(iv, sizeof(iv));
    t = getTime() - t;
    std::cout << "GenIV: " << t << std::endl;
    
    std::string ciphertext;
    std::string decryptedtext;

    try
    {
           // Create Cipher Text
           CryptoPP::AES::Encryption encryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
           CryptoPP::OFB_Mode_ExternalCipher::Encryption modeEncryption( encryption, iv );
           time_t encryptT = getTime();
           CryptoPP::FileSource fs1(filePath.c_str(), true, new CryptoPP::StreamTransformationFilter(modeEncryption, new CryptoPP::StringSink(ciphertext)));
	   encryptT = getTime() - encryptT;
 	   std::cout << "Encrypt: " << encryptT << std::endl;

	
	   // decrypt
    	   CryptoPP::AES::Decryption decryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	   CryptoPP::OFB_Mode_ExternalCipher::Decryption modeDecryption(decryption, iv);
	   time_t decryptT = getTime();
	   CryptoPP::StreamTransformationFilter stfDecryptor(modeDecryption, new CryptoPP::StringSink(decryptedtext) );
	   stfDecryptor.Put( reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	   decryptT = getTime() - decryptT;
	   stfDecryptor.MessageEnd();
	   std::cout << "Decrypt: " << decryptT << std::endl;
    }
    catch( const CryptoPP::Exception& e )
    {
            std::cerr << e.what() << std::endl;
    }

    return 0;
}

int DH(std::string& filePath)
{
 	// Initialize the Diffie-Hellman class with a random prime and base
	CryptoPP::AutoSeededRandomPool rngA;
	CryptoPP::DH dhA;
	dhA.AccessGroupParameters().GenerateRandomWithKeySize(rngA, 56); 
	
	CryptoPP::Integer iPrime = dhA.GetGroupParameters().GetModulus();
	CryptoPP::Integer iGenerator = dhA.GetGroupParameters().GetSubgroupGenerator();

	CryptoPP::SecByteBlock privA(dhA.PrivateKeyLength());
	CryptoPP::SecByteBlock pubA(dhA.PublicKeyLength());
	CryptoPP::SecByteBlock secretKeyA(dhA.AgreedValueLength());

	CryptoPP::AutoSeededRandomPool rngB;
	CryptoPP::DH dhB(iPrime, iGenerator);
	CryptoPP::SecByteBlock privB(dhB.PrivateKeyLength());
	CryptoPP::SecByteBlock pubB(dhB.PublicKeyLength());
	CryptoPP::SecByteBlock secretKeyB(dhB.AgreedValueLength());

	// Generate a pair of integers for Alice. The public integer is forwarded to Bob.
	time_t t = getTime();
	dhA.GenerateKeyPair(rngA, privA, pubA);
	dhB.GenerateKeyPair(rngB, privB, pubB);

	// Agreement
	if (!dhA.Agree(secretKeyA, privA, pubB))
	return 1;
	t = getTime() - t;
	std::cout << "Genkey: " << t << std::endl;
 	//if (!dhB.Agree(secretKeyB, privB, pubA))
	//return 1;

	return DES_CBC(filePath, &secretKeyA);	

}

int RSA(std::string& filePath)
{
        std::string plain;
        std::string cipher;
        std::string recovered;
        std::string beforeRecovered;

        // Generate keys
        time_t t = getTime();
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 1024);
        CryptoPP::RSA::PrivateKey privateKey(params);
        CryptoPP::RSA::PublicKey publicKey(params);
 	t = getTime() - t;
	std::cout << "Genkey: " << t << std::endl;

        // Encryption
        CryptoPP::FileSource loadPlainToString(filePath.c_str(), true, new CryptoPP::StringSink(plain));
        CryptoPP::RSAES_PKCS1v15_Encryptor encrypter(publicKey);

        t = getTime();
        for (int i = 0; i < plain.size(); i+= 117)
        {
                std::string subString = plain.substr(i, 117);
                std::string tmpCipher;
                CryptoPP::StringSource encrypting(subString, true, new CryptoPP::PK_EncryptorFilter(rng, encrypter, new CryptoPP::StringSink(tmpCipher)));
                cipher += tmpCipher;
        }
        t  = getTime() - t;
	std::cout << "Encrypt: " << t << std::endl;

        // Decryption
	CryptoPP::StringSource loadEncryptToString(cipher, true, new CryptoPP::StringSink(beforeRecovered));
        CryptoPP::RSAES_PKCS1v15_Decryptor decrypter(privateKey);

        t = getTime();
        for (int i = 0; i < beforeRecovered.size(); i+= 128)
        {
                std::string subString = beforeRecovered.substr(i, 128);
                std::string tmpPlain;
                CryptoPP::StringSource decrypting(subString, true, new CryptoPP::PK_DecryptorFilter(rng, decrypter, new CryptoPP::StringSink(tmpPlain)));
                recovered += tmpPlain;
        }
        t  = getTime() - t;
	std::cout << "Decrypt: " << t << std::endl;

        return 0;
}

int SHA512(std::string& filePath)
{
        CryptoPP::SHA512 hash;
        std::string digest;

        time_t t = getTime();
        CryptoPP::FileSource f(filePath.c_str(), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
        t = getTime() - t;
	std::cout << "Decrypt: " << t << std::endl;

        return 0;
}

int MD5(const std::string& filePath)
{
        CryptoPP::Weak1::MD5 hash;
        std::string digest;
	
	time_t t = getTime();
        CryptoPP::FileSource f(filePath.c_str(), true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
        t = getTime() - t;
	std::cout << "Decrypt: " << t << std::endl;

        return 0;
}

/**
	args:  File Algorithm Mode
***/
int main(int argc, char *args[]){
	if(argc-1 < 2)
        {
	    std::cout << "Insufficient parameters: File Algorithm Mode" << std::endl;
	    return 1;
	}
	std::string  filePath = args[1];
	std::string algo = args[2];
	std::string mode;
	if(algo == "DES" || algo == "AES")
	{
	    if(args[3] == NULL){
	        std::cout << "Insufficient parameters: File Algorithm Mode" << std::endl;
      	        return 1;
	    }
 	    mode  = args[3];
	} 
	
	if(algo == "DES" ){
		if(mode == "CBC"){
			return DES_CBC(filePath, NULL);
		}else if(mode == "OFB"){
			return DES_OFB(filePath);
		}else{
	    		std::cout << "Unsupported mode" << std::endl;
			return 1;
		}
	} else if(algo == "AES"){
		if(mode == "CBC"){
			return AES_CBC(filePath);
		}else if(mode == "OFB"){
			return AES_OFB(filePath);
		}else{
	    		std::cout << "Unsupported mode" << std::endl;
			return 1;
		}
	} else if(algo == "RSA") {
		return RSA(filePath);
	} else if(algo == "DH") {
		return DH(filePath);
	} else if(algo == "SHA512") {
		return SHA512(filePath);
	} else if(algo == "MD5") {
		return MD5(filePath);
	}
}
