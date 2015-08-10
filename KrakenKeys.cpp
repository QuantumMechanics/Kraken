#include <iostream>
#include <iomanip>
#include <sstream>
#include "sha256.h"
#include <ctype.h>
#include <algorithm>
#include <gmpxx.h> //GNU GMP is used for BigNumer and Base58 encoding.
#include <gmp.h>   //"    "   "  "    "    "        "   "       "
#include <stdarg.h>
#include "cryptopp/ripemd.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include <fstream>
#include "ed25519-donna/ed25519.h"
#include <sodium.h> //for random bytes
#include <bitset> //Data to binary

using namespace std;

// ex: A259BD07F
// = 10 * 16^8 + 2 * 16^7 + 5 * 16^6 + 9 * 16^5 + 11 * 16^4 + 13 * 16^3 + 0 * 16^2 + 7 * 16^1 + 15 * 16^0
// = 43580641407
mpz_class hexaToBigNum (const std::string myString)
{
    std::string hexa_digits = "0123456789ABCDEF";

    int index;
    mpz_class m = 0;

    for( size_t i = 0; i < myString.size(); i++ ) {
        m *= 16;
        index = hexa_digits.find(toupper(myString[i]));
        m += index;
    }

    return m;
}

std::string bigNum2base58 (mpz_class bigNumber)
{
    std::string b58_digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    std::string base58string;
    std::string mycharString;

    mpz_class divisor(58), quotient, remainder;
    mpz_class x = bigNumber;

    while (x > 0) {
    	mpz_fdiv_qr(quotient.get_mpz_t(), remainder.get_mpz_t(), x.get_mpz_t(), divisor.get_mpz_t());
    	mycharString = std::string(1, b58_digits[mpz_get_ui(remainder.get_mpz_t())]);
    	base58string.insert(0, mycharString);
    	x = quotient;
    }

    return base58string;
}

//RAND_bytes Hex conversion
char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string hexStr_secret_key(unsigned char *data, int len)  //Return private key in WIF format
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
           std::string keypair = "80"+ s; //Hex private key starting with 0x80

           std::string keepkeypair = keypair; //We keep the original HEX from keypair

        std::string hashedkeys = sha256(keypair); //We use SHA256 to hash the Hex private key
        std::string twicehashedkeys = sha256(hashedkeys); //We hash the hash
        std::string checksum = twicehashedkeys.substr (0,8); //The first 4 bytes is checksum.
        std::string finalkeys = keepkeypair + checksum; //We add the checksum at the end of the original Hex

        mpz_class bigNumber = 0; //Declaration of BigNumber

       bigNumber = hexaToBigNum(finalkeys); //Convert HEX to BigNumber

        std::string bigNum2base58 (mpz_class); //Convert BigNumber to Base58

        std::string strBase58WIF = bigNum2base58(bigNumber); //Convert Base58 to WIF

  return strBase58WIF;
}

std::string hexStr_public_key(unsigned char *data, int len) //Convert public key to HEX and add 0x04 in front
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }

    std::string hexPublicKey = "04"+ s;

  return hexPublicKey;
}

std::string hexStr_kraken_address(unsigned char *data, int len) //Create KRAKEN Addresses
{
    std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }

    std::string hexPublicKey = "04"+ s;
    std::string hashedPublic = sha256(hexPublicKey); //We use SHA256 to hash the HEX public key

    using namespace CryptoPP; //For RIPEMD160

    CryptoPP::RIPEMD160 hash;
    byte digest[ CryptoPP::RIPEMD160::DIGESTSIZE ];
    std::string message = hashedPublic;

    hash.CalculateDigest( digest, (unsigned char*)message.c_str(), message.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

         std::string RIPEHashedPublic = output; //RIPEMD160 result stored in string
         std:: string RIPEHashedPublicversion = "00" + RIPEHashedPublic; //We add version "1" (0x00) to the string, seems deleted by bigNum, so added again below.

        std::string hashedRIPE = sha256(RIPEHashedPublicversion); //We hash the RIPEMD + version result
        std::string hashedTwiceRIPE = sha256(hashedRIPE); //We hash again the hash of the RIPEMD + version result

        std::string checksum = hashedTwiceRIPE.substr (0,8); //The first 4 bytes is checksum.

        std::string checksumkey = RIPEHashedPublicversion + checksum; //We add the checksum at the end of the original Hex

        mpz_class bigNumberAddress = 0; //Declaration of BigNumber

        bigNumberAddress = hexaToBigNum(checksumkey); //Convert HEX to BigNumber

        std::string bigNum2base58 (mpz_class); //Convert BigNumber to Base58

        std::string strBase58WIFAddress = bigNum2base58(bigNumberAddress); //Convert Base58 to WIF

        std::string Kraken_Address = "1" + strBase58WIFAddress; //Add "1"+ ... to show the leading 1, ignored by bigNum)

        return Kraken_Address;
}


std::string hexStr_signature(unsigned char *data, int len) //Convert signature to HEX
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }

  return s;
}

void CreateKeys()
{
            //Secret key
            ed25519_secret_key sk; 
            randombytes_buf(sk, sizeof(ed25519_secret_key));
            
            //Public key
            ed25519_public_key pk;
            ed25519_publickey(sk, pk);

            //Just testing key conversion
            //// sodium_init();
            //unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
           // unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];

           // crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, pk); //Conversion to curve
          //  crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,sk); //Conversion to curve

            //Display Keypair
            std::cout << "////////////////////////////////////////////////////////////////////////////////" << std::endl;
            std::cout << "Your private key is: " << std::endl;
            std::cout << hexStr_secret_key(sk, sizeof(ed25519_secret_key)) << std::endl; //Converting private key to Hex then WIF
            std::cout << std::endl;
            std::cout << "Your public key is: " << std::endl;
            std::cout << hexStr_public_key(pk, sizeof(ed25519_public_key)) << std::endl; //Converting public key to Hex
            std::cout << std::endl;
            std::cout << "Your address is: " << std::endl;
            std::cout << hexStr_kraken_address(pk, sizeof(ed25519_public_key)) << std::endl;
            std::cout << "////////////////////////////////////////////////////////////////////////////////" << std::endl;
            std::cout << std::endl;

}
///////////////////////////////////////////////////////////////////
