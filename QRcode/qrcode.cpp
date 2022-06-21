#include <iostream>
using namespace std;

#include <cryptopp/aes.h>
using namespace CryptoPP;

int main()
{

        //AES中使用的固定参数是以类AES中定义的enum数据类型出现的，而不是成员函数或变量
        //因此需要用::符号来索引

        cout << "AES Parameters: " << endl;
        cout << "Algorithm name : " << AES::StaticAlgorithmName() << endl;     

        //Crypto++库中一般用字节数来表示长度，而不是常用的字节数
        cout << "Block size     : " << AES::BLOCKSIZE * 8 << endl;
        cout << "Min key length : " << AES::MIN_KEYLENGTH * 8 << endl;
        cout << "Max key length : " << AES::MAX_KEYLENGTH * 8 << endl;

        //AES中只包含一些固定的数据，而加密解密的功能由AESEncryption和AESDecryption来完成
        //加密过程
        AESEncryption aesEncryptor; //加密器

 

        unsigned char aesKey[AES::DEFAULT_KEYLENGTH] = "123456790bmi";                   //密钥

        unsigned char inBlock[AES::BLOCKSIZE];    //要加密的数据块

        unsigned char outBlock[AES::BLOCKSIZE];                                 //加密后的密文块

        unsigned char xorBlock[AES::BLOCKSIZE];                                 //必须设定为全零

        memset( xorBlock, 0, AES::BLOCKSIZE );                                 //置零

 

        aesEncryptor.SetKey( aesKey, AES::DEFAULT_KEYLENGTH );  //设定加密密钥

        aesEncryptor.ProcessAndXorBlock( inBlock, xorBlock, outBlock ); //加密

 

        //以16进制显示加密后的数据

        for( int i=0; i<16; i++ ) {

               cout << hex << (int)outBlock[i] << " ";

       }

        cout << endl;

 

        //解密

        AESDecryption aesDecryptor;

        unsigned char plainText[AES::BLOCKSIZE] = "U2FsdGVkX1+E9fbN2mX+0RL3iPlDfPQp+t4fJCoStIMJVI1NlT5xsnpZ0aqNPzF3xSBuVRyWa0BryWgVlZVdOFfkx09SCFYqPkh+ewrqcOAFuDoTgSB4SjxDav3YdBp8sg1qNxMm8K/Q/dMJtQjDyLUduQMI1y/QOHV+EjG5R5eR+UcbbB9Jtb3F8baP3/Uy4Hc3lidaMX0f6WF8lgCKQg==";

        aesDecryptor.SetKey( aesKey, AES::DEFAULT_KEYLENGTH );

        aesDecryptor.ProcessAndXorBlock( outBlock, xorBlock, plainText );

 

        for( int i=0; i<16; i++ ) {      cout << plainText[i];    }
        cout << endl;

        return 0;
}
