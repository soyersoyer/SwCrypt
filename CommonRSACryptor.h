#pragma once
#include <stdint.h>

typedef uint32_t CCDigestAlgorithm;
typedef int32_t CCCryptorStatus;
typedef uint32_t CCAsymmetricPadding;

typedef struct _CCRSACryptor *CCRSACryptorRef;
CCCryptorStatus CCRSACryptorEncrypt(CCRSACryptorRef publicKey, CCAsymmetricPadding padding, const void *plainText, size_t plainTextLen, void *cipherText, size_t *cipherTextLen, const void *tagData, size_t tagDataLen, CCDigestAlgorithm digestType);
CCCryptorStatus CCRSACryptorDecrypt(CCRSACryptorRef privateKey, CCAsymmetricPadding padding, const void *cipherText, size_t cipherTextLen, void *plainText, size_t *plainTextLen, const void *tagData, size_t tagDataLen, CCDigestAlgorithm digestType);
CCCryptorStatus CCRSACryptorGeneratePair(size_t keysize, uint32_t e, CCRSACryptorRef *publicKey, CCRSACryptorRef *privateKey);
CCRSACryptorRef CCRSACryptorGetPublicKeyFromPrivateKey(CCRSACryptorRef privkey);
void CCRSACryptorRelease(CCRSACryptorRef key);
CCCryptorStatus CCRSACryptorExport(CCRSACryptorRef key, void *out, size_t *outLen);
CCCryptorStatus CCRSACryptorImport(const void *keyPackage, size_t keyPackageLen, CCRSACryptorRef *key);
int CCRSAGetKeySize(CCRSACryptorRef key);
