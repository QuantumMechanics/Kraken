#ifndef KRAKENKEYS_H_INCLUDED
#define KRAKENKEYS_H_INCLUDED

#include <gmpxx.h> //GNU GMP is used for BigNumer and Base58 encoding.
#include <gmp.h>   //"    "   "  "    "    "        "   "       "


void CreateKeys();

mpz_class hexaToBigNum (const std::string myString);
std::string bigNum2base58 (mpz_class bigNumber);

std::string hexStr_secret_key(unsigned char *data, int len);  //Return private key in WIF format
std::string hexStr_public_key(unsigned char *data, int len); //Convert public key to HEX and add 0x04 in front

std::string hexStr_kraken_address(unsigned char *data, int len); //Create KRAKEN Addresses

std::string hexStr_signature(unsigned char *data, int len); //Convert signature to HEX

#endif // KRAKENKEYS_H_INCLUDED
