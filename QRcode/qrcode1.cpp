// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string>

#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using CryptoPP::Exception;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using namespace std;

string encrytByAES(const string &plain, const string &key, const string &iv) {
	string cipher;
	try
	{
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());
 
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}
 
	// Pretty print
	string encoded;
	StringSource(cipher, true,
		new Base64Encoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	return encoded;
}

// 使用AES(CBC模式)解密，encode为base64编码的密文
string decrytByAES(const string &encode, const string &key, const string &iv) {
	string encodeByte;
	StringSource(encode, true, new Base64Decoder(
			new StringSink(encodeByte)
		));
 
	string recovered;
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());
 
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(encodeByte, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}
 
	return recovered;
	//return encodeByte;
}
 
 
int main()
{
	cout << "----------------" << endl
		<< "Start AES test:" << endl;
 
	//byte key[AES::DEFAULT_KEYLENGTH];
	string key = "2022123456790bmi";
	//byte iv[AES::BLOCKSIZE];
	string iv = "2022123456790bmi";
	string plain = "{\"patient\":[{\"name\": \"王紫荆\",\"nation\":\"中国\",\"gender\":\"F\",\"IDtype\":1,\"IDvalue\":510103196502083435}]}";
	//string encoded="LJGU4wJU7o9aVSMRCIUPfS4EO/voIDj43Pjjz9WI5aYLndzShWvL9f4jfMHrKqZ4L1jsH/OFGYgeP4zXhe+n+7bxOW+SC+IsukelD3TShKryM5hatEcFX/Aq4fFXU3CsDNvHHxuoUCNDO8rO2KecFg==";
	

 
	/*********************************\
	\*********************************/
	cout << "密钥key: " << key << endl;
	cout << "初始向量iv: " << iv << endl;
	/*********************************\
	\*********************************/
	cout << "明文plain text: " << plain << endl;
	string encoded = encrytByAES(plain, key, iv);
	cout << "密文cifer text: " << encoded << endl;
	string recovered = decrytByAES(encoded, key, iv);
	cout << "解密recover text: " << recovered << endl;
	return 0;
}
