/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//** Introduction
//
// This file contains implementation of cryptographic primitives for RSA.
// Vendors may replace the implementation in this file with their own library
// functions.

//**  Includes
// Need this define to get the 'private' defines for this function
#define CRYPT_RSA_C
#include "Tpm.h"
#include "swap.h"
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#if     ALG_RSA
#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)
//**  Obligatory Initialization Functions

//*** CryptRsaInit()
// Function called at _TPM_Init().
BOOL
CryptRsaInit(
    void
    )
{
    return TRUE;
}

//*** CryptRsaStartup()
// Function called at TPM2_Startup()
BOOL
CryptRsaStartup(
    void
    )
{
    return TRUE;
}

//** Internal Functions

void
RsaInitializeExponent(
    privateExponent_t      *pExp
    )
{
#if CRT_FORMAT_RSA == NO
    BN_INIT(pExp->D);
#else
    BN_INIT(pExp->Q);
    BN_INIT(pExp->dP);
    BN_INIT(pExp->dQ);
    BN_INIT(pExp->qInv);
#endif
}

//*** ComputePrivateExponent()
static BOOL
ComputePrivateExponent(
    bigNum               P,             // IN: first prime (size is 1/2 of bnN)
    bigNum               Q,             // IN: second prime (size is 1/2 of bnN)
    bigNum               E,             // IN: the public exponent
    bigNum               N,             // IN: the public modulus
    privateExponent_t   *pExp           // OUT:
    )
{
    BOOL                pOK;
    BOOL                qOK;
#if CRT_FORMAT_RSA == NO
    BN_RSA(bnPhi);
//
    RsaInitializeExponent(pExp);
    // Get compute Phi = (p - 1)(q - 1) = pq - p - q + 1 = n - p - q + 1
    pOK = BnCopy(bnPhi, N);
    pOK = pOK && BnSub(bnPhi, bnPhi, P);
    pOK = pOK && BnSub(bnPhi, bnPhi, Q);
    pOK = pOK && BnAddWord(bnPhi, bnPhi, 1);
    // Compute the multiplicative inverse d = 1/e mod Phi
    pOK = pOK && BnModInverse((bigNum)&pExp->D, E, bnPhi);
    qOK = pOK;
#else
    BN_PRIME(temp);
    bigNum              pT;
//
    NOT_REFERENCED(N);
    RsaInitializeExponent(pExp);
    BnCopy((bigNum)&pExp->Q, Q);

    // make p the larger value so that m2 is always less than p
    if(BnUnsignedCmp(P, Q) < 0)
    {
        pT = P;
        P = Q;
        Q = pT;
    }
    //dP = (1/e) mod (p-1) = d mod (p-1)
    pOK = BnSubWord(temp, P, 1);
    pOK = pOK && BnModInverse((bigNum)&pExp->dP, E, temp);
    //dQ = (1/e) mod (q-1) = d mod (q-1)
    qOK = BnSubWord(temp, Q, 1);
    qOK = qOK && BnModInverse((bigNum)&pExp->dQ, E, temp);
    // qInv = (1/q) mod p
    if(pOK && qOK)
        pOK = qOK = BnModInverse((bigNum)&pExp->qInv, Q, P);
#endif
    if(!pOK)
        BnSetWord(P, 0);
    if(!qOK)
        BnSetWord(Q, 0);

    return pOK && qOK;

}


//*** RsaPrivateKeyOp()
// This function is called to do the exponentiation with the private key. Compile
// options allow use of the simple (but slow) private exponent, or the more complex
// but faster CRT method.
static BOOL
RsaPrivateKeyOp(
    bigNum               inOut, // IN/OUT: number to be exponentiated
    bigNum               N,     // IN: public modulus (can be NULL if CRT)
    bigNum               P,     // IN: one of the primes (can be NULL if not CRT)
    privateExponent_t   *pExp
    )
{
    BOOL                 OK;

#if CRT_FORMAT_RSA == NO
    (P);
    OK = BnModExp(inOut, inOut, (bigNum)&pExp->D, N);
#else
    BN_RSA(M1);
    BN_RSA(M2);
    BN_RSA(M);
    BN_RSA(H);
    bigNum              Q = (bigNum)&pExp->Q;
    NOT_REFERENCED(N);
    // Make P the larger prime.
    // NOTE that when the CRT form of the private key is created, dP will always
    // be computed using the larger of p and q so the only thing needed here is that
    // the primes be selected so that they agree with dP.
    if(BnUnsignedCmp(P, Q) < 0)
    {
        bigNum      T = P;
        P = Q;
        Q = T;
    }
    // m1 = cdP mod p
    OK = BnModExp(M1, inOut, (bigNum)&pExp->dP, P);
    // m2 = cdQ mod q
    OK = OK && BnModExp(M2, inOut, (bigNum)&pExp->dQ, Q);
    // h = qInv * (m1 - m2) mod p = qInv * (m1 + P - m2) mod P because Q < P
    // so m2 < P
    OK = OK && BnSub(H, P, M2);
    OK = OK && BnAdd(H, H, M1);
    OK = OK && BnModMult(H, H, (bigNum)&pExp->qInv, P);
    // m = m2 + h * q
    OK = OK && BnMult(M, H, Q);
    OK = OK && BnAdd(inOut, M2, M);
#endif
    return OK;
}

//*** RSAEP()
// This function performs the RSAEP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('m') with the public exponent ('e'), modulo
// the public ('n').
//
//  return type: TPM_RC
//      TPM_RC_VALUE     number to exponentiate is larger than the modulus
//
static TPM_RC
RSAEP(
    TPM2B       *dInOut,        // IN: size of the encrypted block and the size of
                                //     the encrypted value. It must be the size of
                                //     the modulus.
                                // OUT: the encrypted data. Will receive the
                                //      decrypted value
    OBJECT      *key            // IN: the key to use
    )
{
    TPM2B_TYPE(4BYTES, 4);
    TPM2B_4BYTES(e) = {{4, {(BYTE)((RSA_DEFAULT_PUBLIC_EXPONENT >> 24) & 0xff),
                           (BYTE)((RSA_DEFAULT_PUBLIC_EXPONENT >> 16) & 0xff),
                           (BYTE)((RSA_DEFAULT_PUBLIC_EXPONENT >> 8) & 0xff),
                           (BYTE)((RSA_DEFAULT_PUBLIC_EXPONENT)& 0xff)}}};
//
    if(key->publicArea.parameters.rsaDetail.exponent != 0)
        UINT32_TO_BYTE_ARRAY(key->publicArea.parameters.rsaDetail.exponent,
                             e.t.buffer);

    return ModExpB(dInOut->size, dInOut->buffer, dInOut->size, dInOut->buffer,
                   e.t.size, e.t.buffer, key->publicArea.unique.rsa.t.size,
                   key->publicArea.unique.rsa.t.buffer);
}

//*** RSADP()
// This function performs the RSADP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('c') with the private exponent ('d'), modulo
// the public modulus ('n'). The decryption is in place.
//
// This function also checks the size of the private key. If the size indicates
// that only a prime value is present, the key is converted to being a private
// exponent.
//
//  return type: TPM_RC
//      TPM_RC_SIZE         the value to decrypt is larger than the modulus
//
static TPM_RC
RSADP(
    TPM2B           *inOut,        // IN/OUT: the value to encrypt
    OBJECT          *key           // IN: the key
    )
{
    BN_RSA_INITIALIZED(bnM, inOut);
    BN_RSA_INITIALIZED(bnN, &key->publicArea.unique.rsa);
    BN_RSA_INITIALIZED(bnP, &key->sensitive.sensitive.rsa);
    if(BnUnsignedCmp(bnM, bnN) >= 0)
        return TPM_RC_SIZE;
    // private key operation requires that private exponent be loaded
    // During self-test, this might not be the case so load it up if it hasn't 
    // already done
    // been done
    if(!key->attributes.privateExp)
        CryptRsaLoadPrivateExponent(key);

    if(!RsaPrivateKeyOp(bnM, bnN, bnP, &key->privateExponent))
        FAIL(FATAL_ERROR_INTERNAL);
    BnTo2B(bnM, inOut, inOut->size);
    return TPM_RC_SUCCESS;
}

static TPM_RC
RSAInitializePrivate(
    TPM2B           *inOut,        // IN/OUT: the value to encrypt
    OBJECT          *key           // IN: the key
    )
{
    BN_RSA_INITIALIZED(bnM, inOut);
    BN_RSA_INITIALIZED(bnN, &key->publicArea.unique.rsa);
    BN_RSA_INITIALIZED(bnP, &key->sensitive.sensitive.rsa);
    if(BnUnsignedCmp(bnM, bnN) >= 0)
        return TPM_RC_SIZE;
    // private key operation requires that private exponent be loaded
    // During self-test, this might not be the case so load it up if it hasn't 
    // already done
    // been done
    if(!key->attributes.privateExp)
        CryptRsaLoadPrivateExponent(key);
    return TPM_RC_SUCCESS;
}

//*** OaepEncode()
// This function performs OAEP padding. The size of the buffer to receive the
// OAEP padded data must equal the size of the modulus
//
// return type: TPM_RC
//  TPM_RC_VALUE     'hashAlg' is not valid or message size is too large
//
static TPM_RC
OaepEncode(
    TPM2B       *padded,        // OUT: the pad data
    TPM_ALG_ID   hashAlg,       // IN: algorithm to use for padding
    const TPM2B *label,         // IN: null-terminated string (may be NULL)
    TPM2B       *message,       // IN: the message being padded
    RAND_STATE  *rand           // IN: the random number generator to use
    )
{
    INT32        padLen;
    INT32        dbSize;
    INT32        i;
    BYTE         mySeed[MAX_DIGEST_SIZE];
    BYTE        *seed = mySeed;
    INT32        hLen = CryptHashGetDigestSize(hashAlg);
    BYTE         mask[MAX_RSA_KEY_BYTES];
    BYTE        *pp;
    BYTE        *pm;
    TPM_RC       retVal = TPM_RC_SUCCESS;

    pAssert(padded != NULL && message != NULL);

    // A value of zero is not allowed because the KDF can't produce a result
    // if the digest size is zero.
    if(hLen <= 0)
        return TPM_RC_VALUE;

    // Basic size checks
    //  make sure digest isn't too big for key size
    if(padded->size < (2 * hLen) + 2)
        ERROR_RETURN(TPM_RC_HASH);

    // and that message will fit messageSize <= k - 2hLen - 2
    if(message->size > (padded->size - (2 * hLen) - 2))
        ERROR_RETURN(TPM_RC_VALUE);

    // Hash L even if it is null
    // Offset into padded leaving room for masked seed and byte of zero
    pp = &padded->buffer[hLen + 1];
    if(CryptHashBlock(hashAlg, label->size, (BYTE *)label->buffer,
                      hLen, pp) != hLen)
        ERROR_RETURN(TPM_RC_FAILURE);

    // concatenate PS of k  mLen  2hLen  2
    padLen = padded->size - message->size - (2 * hLen) - 2;
    MemorySet(&pp[hLen], 0, padLen);
    pp[hLen + padLen] = 0x01;
    padLen += 1;
    memcpy(&pp[hLen + padLen], message->buffer, message->size);

    // The total size of db = hLen + pad + mSize;
    dbSize = hLen + padLen + message->size;

    // If testing, then use the provided seed. Otherwise, use values
    // from the RNG
    CryptRandomGenerate(hLen, mySeed);
    DRBG_Generate(rand, mySeed, (UINT16)hLen);
    // mask = MGF1 (seed, nSize  hLen  1)
    CryptMGF1(dbSize, mask, hashAlg, hLen, seed);

    // Create the masked db
    pm = mask;
    for(i = dbSize; i > 0; i--)
        *pp++ ^= *pm++;
    pp = &padded->buffer[hLen + 1];

    // Run the masked data through MGF1
    if(CryptMGF1(hLen, &padded->buffer[1], hashAlg, dbSize, pp) != (unsigned)hLen)
        ERROR_RETURN(TPM_RC_VALUE);
// Now XOR the seed to create masked seed
    pp = &padded->buffer[1];
    pm = seed;
    for(i = hLen; i > 0; i--)
        *pp++ ^= *pm++;
    // Set the first byte to zero
    padded->buffer[0] = 0x00;
Exit:
    return retVal;
}

//*** OaepDecode()
// This function performs OAEP padding checking. The size of the buffer to receive
// the recovered data. If the padding is not valid, the 'dSize' size is set to zero
// and the function returns TPM_RC_VALUE.
//
// The 'dSize' parameter is used as an input to indicate the size available in the
// buffer.

// If insufficient space is available, the size is not changed and the return code
// is TPM_RC_VALUE.
//
//  return type:    TPM_RC
//      TPM_RC_VALUE        the value to decode was larger than the modulus, or
//                          the padding is wrong or the buffer to receive the
//                          results is too small
//
//
static TPM_RC
OaepDecode(
    TPM2B           *dataOut,       // OUT: the recovered data
    TPM_ALG_ID       hashAlg,       // IN: algorithm to use for padding
    const TPM2B     *label,         // IN: null-terminated string (may be NULL)
    TPM2B           *padded         // IN: the padded data
    )
{
    UINT32       i;
    BYTE         seedMask[MAX_DIGEST_SIZE];
    UINT32       hLen = CryptHashGetDigestSize(hashAlg);

    BYTE         mask[MAX_RSA_KEY_BYTES];
    BYTE        *pp;
    BYTE        *pm;
    TPM_RC       retVal = TPM_RC_SUCCESS;

    // Strange size (anything smaller can't be an OAEP padded block)
    // Also check for no leading 0
    if((padded->size < (unsigned)((2 * hLen) + 2)) || (padded->buffer[0] != 0))
        ERROR_RETURN(TPM_RC_VALUE);
// Use the hash size to determine what to put through MGF1 in order
// to recover the seedMask
    CryptMGF1(hLen, seedMask, hashAlg, padded->size - hLen - 1,
              &padded->buffer[hLen + 1]);

    // Recover the seed into seedMask
    pAssert(hLen <= sizeof(seedMask));
    pp = &padded->buffer[1];
    pm = seedMask;
    for(i = hLen; i > 0; i--)
        *pm++ ^= *pp++;

    // Use the seed to generate the data mask
    CryptMGF1(padded->size - hLen - 1, mask, hashAlg, hLen, seedMask);

    // Use the mask generated from seed to recover the padded data
    pp = &padded->buffer[hLen + 1];
    pm = mask;
    for(i = (padded->size - hLen - 1); i > 0; i--)
        *pm++ ^= *pp++;

    // Make sure that the recovered data has the hash of the label
    // Put trial value in the seed mask
    if((CryptHashBlock(hashAlg, label->size, (BYTE *)label->buffer,
                       hLen, seedMask)) != hLen)
        FAIL(FATAL_ERROR_INTERNAL);
    if(memcmp(seedMask, mask, hLen) != 0)
        ERROR_RETURN(TPM_RC_VALUE);

    // find the start of the data
    pm = &mask[hLen];
    for(i = (UINT32)padded->size - (2 * hLen) - 1; i > 0; i--)
    {
        if(*pm++ != 0)
            break;
    }
    // If we ran out of data or didn't end with 0x01, then return an error
    if(i == 0 || pm[-1] != 0x01)
        ERROR_RETURN(TPM_RC_VALUE);

    // pm should be pointing at the first part of the data
    // and i is one greater than the number of bytes to move
    i--;
    if(i > dataOut->size)
        // Special exit to preserve the size of the output buffer
        return TPM_RC_VALUE;
    memcpy(dataOut->buffer, pm, i);
    dataOut->size = (UINT16)i;
Exit:
    if(retVal != TPM_RC_SUCCESS)
        dataOut->size = 0;
    return retVal;
}

//*** PKCS1v1_5Encode()
// This function performs the encoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//  return type:    TPM_RC
//  TPM_RC_VALUE     message size is too large
//
static TPM_RC
RSAES_PKCS1v1_5Encode(
    TPM2B       *padded,        // OUT: the pad data
    TPM2B       *message,       // IN: the message being padded
    RAND_STATE  *rand
    )
{
    DMSG("RSAES_PKCS1v1_5Encode Padding"); 
    UINT32      ps = padded->size - message->size - 3;
//
    if(message->size > padded->size - 11)
        return TPM_RC_VALUE;
    // move the message to the end of the buffer
    memcpy(&padded->buffer[padded->size - message->size], message->buffer,
           message->size);
    // Set the first byte to 0x00 and the second to 0x02
    padded->buffer[0] = 0;
    padded->buffer[1] = 2;

    // Fill with random bytes
    DRBG_Generate(rand, &padded->buffer[2], (UINT16)ps);

    // Set the delimiter for the random field to 0
    padded->buffer[2 + ps] = 0;

    // Now, the only messy part. Make sure that all the 'ps' bytes are non-zero
    // In this implementation, use the value of the current index
    for(ps++; ps > 1; ps--)
    {
        if(padded->buffer[ps] == 0)
            padded->buffer[ps] = 0x55;  // In the < 0.5% of the cases that the
                                        // random value is 0, just pick a value to
                                        // put into the spot.
    }
    return TPM_RC_SUCCESS;
}

//*** RSAES_Decode()
// This function performs the decoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//
//  return type:    TPM_RC
//      TPM_RC_FAIL      decoding error or results would no fit into provided buffer
//
static TPM_RC
RSAES_Decode(
    TPM2B       *message,       // OUT: the recovered message
    TPM2B       *coded          // IN: the encoded message
    )
{
    BOOL        fail = FALSE;
    UINT16      pSize;

    fail = (coded->size < 11);
    fail = (coded->buffer[0] != 0x00) | fail;
    fail = (coded->buffer[1] != 0x02) | fail;
    for(pSize = 2; pSize < coded->size; pSize++)
    {
        if(coded->buffer[pSize] == 0)
            break;
    }
    pSize++;

    // Make sure that pSize has not gone over the end and that there are at least 8
    // bytes of pad data.
    fail = (pSize >= coded->size) | fail;
    fail = ((pSize - 2) < 8) | fail;
    if((message->size < (UINT16)(coded->size - pSize)) || fail)
        return TPM_RC_VALUE;
    message->size = coded->size - pSize;
    memcpy(message->buffer, &coded->buffer[pSize], coded->size - pSize);
    return TPM_RC_SUCCESS;
}

//*** PssEncode()
// This function creates an encoded block of data that is the size of modulus.
// The function uses the maximum salt size that will fit in the encoded block.
//
//  Returns TPM_RC_SUCCESS or goes into failure mode.
static TPM_RC
PssEncode(
    TPM2B           *out,       // OUT: the encoded buffer
    TPM_ALG_ID       hashAlg,   // IN: hash algorithm for the encoding
    TPM2B           *digest,    // IN: the digest
    RAND_STATE      *rand       // IN: random number source
    )
{
    UINT32               hLen = CryptHashGetDigestSize(hashAlg);
    BYTE                 salt[MAX_RSA_KEY_BYTES - 1];
    UINT16               saltSize;
    BYTE                *ps = salt;
    BYTE                *pOut;
    UINT16               mLen;
    HASH_STATE           hashState;

    // These are fatal errors indicating bad TPM firmware
    pAssert(out != NULL && hLen > 0 && digest != NULL);

    // Get the size of the mask
    mLen = (UINT16)(out->size - hLen - 1);

    // Maximum possible salt size is mask length - 1
    saltSize = mLen - 1;

    // Use the maximum salt size allowed by FIPS 186-4
    if(saltSize > hLen)
        saltSize = (UINT16)hLen;

//using eOut for scratch space
    // Set the first 8 bytes to zero
    pOut = out->buffer;
    memset(pOut, 0, 8);

    // Get set the salt
    DRBG_Generate(rand, salt, saltSize);

    // Create the hash of the pad || input hash || salt
    CryptHashStart(&hashState, hashAlg);
    CryptDigestUpdate(&hashState, 8, pOut);
    CryptDigestUpdate2B(&hashState, digest);
    CryptDigestUpdate(&hashState, saltSize, salt);
    CryptHashEnd(&hashState, hLen, &pOut[out->size - hLen - 1]);

    // Create a mask
    if(CryptMGF1(mLen, pOut, hashAlg, hLen, &pOut[mLen]) != mLen)
        FAIL(FATAL_ERROR_INTERNAL);

    // Since this implementation uses key sizes that are all even multiples of
    // 8, just need to make sure that the most significant bit is CLEAR
    *pOut &= 0x7f;

    // Before we mess up the pOut value, set the last byte to 0xbc
    pOut[out->size - 1] = 0xbc;

    // XOR a byte of 0x01 at the position just before where the salt will be XOR'ed
    pOut = &pOut[mLen - saltSize - 1];
    *pOut++ ^= 0x01;

    // XOR the salt data into the buffer
    for(; saltSize > 0; saltSize--)
        *pOut++ ^= *ps++;

    // and we are done
    return TPM_RC_SUCCESS;
}

//*** PssDecode()
// This function checks that the PSS encoded block was built from the
// provided digest. If the check is successful, TPM_RC_SUCCESS is returned.
// Any other value indicates an error.
//
// This implementation of PSS decoding is intended for the reference TPM
// implementation and is not at all generalized.  It is used to check
// signatures over hashes and assumptions are made about the sizes of values.
// Those assumptions are enforce by this implementation.
// This implementation does allow for a variable size salt value to have been
// used by the creator of the signature.
//
//  return type:    TPM_RC
//      TPM_RC_SCHEME       'hashAlg' is not a supported hash algorithm
//      TPM_RC_VALUE         decode operation failed
//
static TPM_RC
PssDecode(
    TPM_ALG_ID   hashAlg,        // IN: hash algorithm to use for the encoding
    TPM2B       *dIn,            // In: the digest to compare
    TPM2B       *eIn             // IN: the encoded data
    )
{
    UINT32           hLen = CryptHashGetDigestSize(hashAlg);
    BYTE             mask[MAX_RSA_KEY_BYTES];
    BYTE            *pm = mask;
    BYTE            *pe;
    BYTE             pad[8] = {0};
    UINT32           i;
    UINT32           mLen;
    BYTE             fail;
    TPM_RC           retVal = TPM_RC_SUCCESS;
    HASH_STATE       hashState;

    // These errors are indicative of failures due to programmer error
    pAssert(dIn != NULL && eIn != NULL);
    pe = eIn->buffer;

    // check the hash scheme
    if(hLen == 0)
        ERROR_RETURN(TPM_RC_SCHEME);

    // most significant bit must be zero
    fail = pe[0] & 0x80;

    // last byte must be 0xbc
    fail |= pe[eIn->size - 1] ^ 0xbc;

    // Use the hLen bytes at the end of the buffer to generate a mask
    // Doesn't start at the end which is a flag byte
    mLen = eIn->size - hLen - 1;
    CryptMGF1(mLen, mask, hashAlg, hLen, &pe[mLen]);

    // Clear the MSO of the mask to make it consistent with the encoding.
    mask[0] &= 0x7F;

    pAssert(mLen <= sizeof(mask));
    // XOR the data into the mask to recover the salt. This sequence
    // advances eIn so that it will end up pointing to the seed data
    // which is the hash of the signature data
    for(i = mLen; i > 0; i--)
        *pm++ ^= *pe++;

    // Find the first byte of 0x01 after a string of all 0x00
    for(pm = mask, i = mLen; i > 0; i--)
    {
        if(*pm == 0x01)
            break;
        else
            fail |= *pm++;
    }
    // i should not be zero
    fail |= (i == 0);

    // if we have failed, will continue using the entire mask as the salt value so
    // that the timing attacks will not disclose anything (I don't think that this
    // is a problem for TPM applications but, usually, we don't fail so this
    // doesn't cost anything).
    if(fail)
    {
        i = mLen;
        pm = mask;
    }
    else
    {
        pm++;
        i--;
    }
    // i contains the salt size and pm points to the salt. Going to use the input
    // hash and the seed to recreate the hash in the lower portion of eIn.
    CryptHashStart(&hashState, hashAlg);

    // add the pad of 8 zeros
    CryptDigestUpdate(&hashState, 8, pad);

    // add the provided digest value
    CryptDigestUpdate(&hashState, dIn->size, dIn->buffer);

    // and the salt
    CryptDigestUpdate(&hashState, i, pm);

    // get the result
    fail |= (CryptHashEnd(&hashState, hLen, mask) != hLen);

    // Compare all bytes
    for(pm = mask; hLen > 0; hLen--)
        // don't use fail = because that could skip the increment and compare
        // operations after the first failure and that gives away timing
        // information.
        fail |= *pm++ ^ *pe++;

    retVal = (fail != 0) ? TPM_RC_VALUE : TPM_RC_SUCCESS;
Exit:
        return retVal;
}

//*** RSASSA_Encode()
// Encode a message using PKCS1v1.5 method.
//
//  return type:    TPM_RC
//      TPM_RC_SCHEME       'hashAlg' is not a supported hash algorithm
//      TPM_RC_SIZE         'eOutSize' is not large enough
//      TPM_RC_VALUE        'hInSize' does not match the digest size of hashAlg
static TPM_RC
RSASSA_Encode(
    TPM2B               *pOut,      // IN:OUT on in, the size of the public key
                                    //        on out, the encoded area
    TPM_ALG_ID           hashAlg,   // IN: hash algorithm for PKCS1v1_5
    TPM2B               *hIn        // IN: digest value to encode
    )
{
    const BYTE      *der;
    BYTE            *eOut;
    INT32            derSize = CryptHashGetDer(hashAlg, &der);
    INT32            fillSize;
    TPM_RC           retVal = TPM_RC_SUCCESS;

    // Can't use this scheme if the algorithm doesn't have a DER string defined.
    if(derSize == 0)
        ERROR_RETURN(TPM_RC_SCHEME);

    // If the digest size of 'hashAl' doesn't match the input digest size, then
    // the DER will misidentify the digest so return an error
    if(CryptHashGetDigestSize(hashAlg) != hIn->size)
        ERROR_RETURN(TPM_RC_VALUE);
    fillSize = pOut->size - derSize - hIn->size - 3;
    eOut = pOut->buffer;

    // Make sure that this combination will fit in the provided space
    if(fillSize < 8)
        ERROR_RETURN(TPM_RC_SIZE);
    // Start filling
    *eOut++ = 0; // initial byte of zero
    *eOut++ = 1; // byte of 0x01
    for(; fillSize > 0; fillSize--)
        *eOut++ = 0xff; // bunch of 0xff
    *eOut++ = 0; // another 0
    for(; derSize > 0; derSize--)
        *eOut++ = *der++;   // copy the DER
    der = hIn->buffer;
    for(fillSize = hIn->size; fillSize > 0; fillSize--)
        *eOut++ = *der++;   // copy the hash
Exit:
    return retVal;
}

//*** RSASSA_Decode()
// This function performs the RSASSA decoding of a signature.
//
//  return type:    TPM_RC
//      TPM_RC_VALUE          decode unsuccessful
//      TPM_RC_SCHEME        'haslAlg' is not supported
//
static TPM_RC
RSASSA_Decode(
    TPM_ALG_ID       hashAlg,        // IN: hash algorithm to use for the encoding
    TPM2B           *hIn,            // In: the digest to compare
    TPM2B           *eIn             // IN: the encoded data
    )
{
    BYTE             fail;
    const BYTE      *der;
    BYTE            *pe;
    INT32            derSize = CryptHashGetDer(hashAlg, &der);
    INT32            hashSize = CryptHashGetDigestSize(hashAlg);
    INT32            fillSize;
    TPM_RC           retVal;
    BYTE            *digest;
    UINT16           digestSize;

    pAssert(hIn != NULL && eIn != NULL);
    pe = eIn->buffer;

    // Can't use this scheme if the algorithm doesn't have a DER string
    // defined or if the provided hash isn't the right size
    if(derSize == 0 || (unsigned)hashSize != hIn->size)
        ERROR_RETURN(TPM_RC_SCHEME);

    // Make sure that this combination will fit in the provided space
    // Since no data movement takes place, can just walk though this
    // and accept nearly random values. This can only be called from
    // CryptValidateSignature() so eInSize is known to be in range.
    fillSize = eIn->size - derSize - hashSize - 3;

    // Start checking (fail will become non-zero if any of the bytes do not have
    // the expected value.
    fail = *pe++;                   // initial byte of zero
    fail |= *pe++ ^ 1;              // byte of 0x01
    for(; fillSize > 0; fillSize--)
        fail |= *pe++ ^ 0xff;       // bunch of 0xff
    fail |= *pe++;                  // another 0
    for(; derSize > 0; derSize--)
        fail |= *pe++ ^ *der++;    // match the DER
    digestSize = hIn->size;
    digest = hIn->buffer;
    for(; digestSize > 0; digestSize--)
        fail |= *pe++ ^ *digest++; // match the hash
    retVal = (fail != 0) ? TPM_RC_VALUE : TPM_RC_SUCCESS;
Exit:
    return retVal;
}

//** Externally Accessible Functions

//*** CryptRsaSelectScheme()
// This function is used by TPM2_RSA_Decrypt and TPM2_RSA_Encrypt.  It sets up
// the rules to select a scheme between input and object default.
// This function assume the RSA object is loaded.
// If a default scheme is defined in object, the default scheme should be chosen,
// otherwise, the input scheme should be chosen.
// In the case that both the object and 'scheme' are not TPM_ALG_NULL, then
// if the schemes are the same, the input scheme will be chosen.
// if the scheme are not compatible, a NULL pointer will be returned.
//
// The return pointer may point to a TPM_ALG_NULL scheme.
TPMT_RSA_DECRYPT*
CryptRsaSelectScheme(
    TPMI_DH_OBJECT       rsaHandle,     // IN: handle of an RSA key
    TPMT_RSA_DECRYPT    *scheme         // IN: a sign or decrypt scheme
    )
{
    OBJECT              *rsaObject;
    TPMT_ASYM_SCHEME    *keyScheme;
    TPMT_RSA_DECRYPT    *retVal = NULL;

    // Get sign object pointer
    rsaObject = HandleToObject(rsaHandle);
    keyScheme = &rsaObject->publicArea.parameters.asymDetail.scheme;

    // if the default scheme of the object is TPM_ALG_NULL, then select the
    // input scheme
    if(keyScheme->scheme == TPM_ALG_NULL)
    {
        retVal = scheme;
    }
    // if the object scheme is not TPM_ALG_NULL and the input scheme is
    // ALG_NULL, then select the default scheme of the object.
    else if(scheme->scheme == TPM_ALG_NULL)
    {
        // if input scheme is NULL
        retVal = (TPMT_RSA_DECRYPT *)keyScheme;
    }
    // get here if both the object scheme and the input scheme are
    // not TPM_ALG_NULL. Need to insure that they are the same.
    // IMPLEMENTATION NOTE: This could cause problems if future versions have
    // schemes that have more values than just a hash algorithm. A new function
    // (IsSchemeSame()) might be needed then.
    else if(keyScheme->scheme == scheme->scheme
            && keyScheme->details.anySig.hashAlg == scheme->details.anySig.hashAlg)
    {
        retVal = scheme;
    }
    // two different, incompatible schemes specified will return NULL
    return retVal;
}

//*** CryptRsaLoadPrivateExponent()
// This function is called to generate the private exponent of an RSA key. //
// return type: TPM_RC
//  TPM_RC_BINDING      public and private parts of 'rsaKey' are not matched
TPM_RC
CryptRsaLoadPrivateExponent(
    OBJECT          *rsaKey        // IN: the RSA key object
    )
{
    
    BN_RSA_INITIALIZED(bnN, &rsaKey->publicArea.unique.rsa);
    BN_PRIME_INITIALIZED(bnP, &rsaKey->sensitive.sensitive.rsa);
    BN_RSA(bnQ);
    BN_PRIME(bnQr);
    BN_WORD_INITIALIZED(bnE, (rsaKey->publicArea.parameters.rsaDetail.exponent == 0)
                        ? RSA_DEFAULT_PUBLIC_EXPONENT
                        : rsaKey->publicArea.parameters.rsaDetail.exponent);
    TPM_RC          retVal = TPM_RC_SUCCESS;
    if(!rsaKey->attributes.privateExp)
    {
        TEST(ALG_NULL_VALUE);

        // Make sure that the bigNum used for the exponent is properly initialized
        RsaInitializeExponent(&rsaKey->privateExponent);

        // Find the second prime by division
        BnDiv(bnQ, bnQr, bnN, bnP);
        if(!BnEqualZero(bnQr))
            ERROR_RETURN(TPM_RC_BINDING);
        // Compute the private exponent and return it if found
        if(!ComputePrivateExponent(bnP, bnQ, bnE, bnN,
                                   &rsaKey->privateExponent))
            ERROR_RETURN(TPM_RC_BINDING);
    }
Exit:
    rsaKey->attributes.privateExp = (retVal == TPM_RC_SUCCESS);
    return retVal;
}

//*** CryptRsaEncrypt()
// This is the entry point for encryption using RSA. Encryption is
// use of the public exponent. The padding parameter determines what
// padding will be used.
//
// The 'cOutSize' parameter must be at least as large as the size of the key.
//
// If the padding is RSA_PAD_NONE, 'dIn' is treated as a number. It must be
// lower in value than the key modulus.
// NOTE: If dIn has fewer bytes than cOut, then we don't add low-order zeros to
//       dIn to make it the size of the RSA key for the call to RSAEP. This is
//       because the high order bytes of dIn might have a numeric value that is
//       greater than the value of the key modulus. If this had low-order zeros
//       added, it would have a numeric value larger than the modulus even though
//       it started out with a lower numeric value.
//
//  return type:    TPM_RC
//      TPM_RC_VALUE     'cOutSize' is too small (must be the size
//                        of the modulus)
//      TPM_RC_SCHEME    'padType' is not a supported scheme
//
LIB_EXPORT TPM_RC
CryptRsaEncrypt(
    TPM2B_PUBLIC_KEY_RSA        *cOut,          // OUT: the encrypted data
    TPM2B                       *dIn,           // IN: the data to encrypt
    OBJECT                      *key,           // IN: the key used for encryption
    TPMT_RSA_DECRYPT            *scheme,        // IN: the type of padding and hash
                                                //     if needed
    const TPM2B                 *label,         // IN: in case it is needed
    RAND_STATE                  *rand           // IN: random number generator
                                                //     state (mostly for testing)
    )
{
    TPM_RC                       retVal = TPM_RC_SUCCESS;
    TPM2B_PUBLIC_KEY_RSA         dataIn;
//
    // if the input and output buffers are the same, copy the input to a scratch
    // buffer so that things don't get messed up.
    if(dIn == &cOut->b)
    {
        MemoryCopy2B(&dataIn.b, dIn, sizeof(dataIn.t.buffer));
        dIn = &dataIn.b;
    }
    // All encryption schemes return the same size of data
    cOut->t.size = key->publicArea.unique.rsa.t.size;
    TEST(scheme->scheme);
    uint8_t useHACrypto = 1;
    switch(scheme->scheme)
    {
        case ALG_NULL_VALUE:  // 'raw' encryption
        {
            INT32            i;
            INT32            dSize = dIn->size;
            // dIn can have more bytes than cOut as long as the extra bytes
            // are zero. Note: the more significant bytes of a number in a byte
            // buffer are the bytes at the start of the array.
            for(i = 0; (i < dSize) && (dIn->buffer[i] == 0); i++);
            dSize -= i;
            if(dSize > cOut->t.size)
                ERROR_RETURN(TPM_RC_VALUE);
            // Pad cOut with zeros if dIn is smaller
            memset(cOut->t.buffer, 0, cOut->t.size - dSize);
            // And copy the rest of the value
            memcpy(&cOut->t.buffer[cOut->t.size - dSize], &dIn->buffer[i], dSize);

            // If the size of dIn is the same as cOut dIn could be larger than
            // the modulus. If it is, then RSAEP() will catch it.
        }
        break;
        case ALG_RSAES_VALUE:
            retVal = useHACrypto ? TPM_RC_SUCCESS : RSAES_PKCS1v1_5Encode(&cOut->b, dIn, rand);
            break;
        case ALG_OAEP_VALUE:
            retVal = OaepEncode(&cOut->b, scheme->details.oaep.hashAlg, label, dIn,
                                rand);
            break;
        default:
            ERROR_RETURN(TPM_RC_SCHEME);
            break;
    }
    // All the schemes that do padding will come here for the encryption step
    // Check that the Encoding worked
    if(retVal == TPM_RC_SUCCESS) {
        // Padding OK so do the encryption
        if((!useHACrypto) || (scheme->scheme != ALG_RSAES_VALUE)) {
            retVal = RSAEP(&cOut->b, key);
        } else {
            TEE_Result ret = TEE_SUCCESS; // return code        
            TEE_ObjectHandle tee_key = (TEE_ObjectHandle) NULL;
            TEE_Attribute rsa_attrs[3];
            void *to_encrypt = NULL;
            uint32_t cipher_len = key->publicArea.unique.rsa.t.size;
            void *cipher = NULL;
            TEE_ObjectInfo info;
            TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
            uint16_t in_len = (uint16_t)dIn->size;


            uint8_t public_key[3] = {0x01, 0x00, 0x01};

            
            // modulus
            rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
            rsa_attrs[0].content.ref.buffer = (uint8_t *)key->publicArea.unique.rsa.t.buffer;
            rsa_attrs[0].content.ref.length = (uint16_t)key->publicArea.unique.rsa.t.size;
            // Public key
            rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
            rsa_attrs[1].content.ref.buffer = public_key;
            rsa_attrs[1].content.ref.length = 3;
            // Private key
            rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
            rsa_attrs[2].content.ref.buffer = (uint8_t *)key->sensitive.sensitive.rsa.t.buffer;
            rsa_attrs[2].content.ref.length = (uint16_t)key->sensitive.sensitive.rsa.t.size;
            
            DMSG("Setting key size to %d and message size to %d", (key->publicArea.unique.rsa.t.size * 8), in_len);
            // create a transient object
            ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, (key->publicArea.unique.rsa.t.size * 8), &tee_key);
            if (ret != TEE_SUCCESS) {
              DMSG("Error");
            }

            // populate the object with your keys
            ret = TEE_PopulateTransientObject(tee_key, (TEE_Attribute *)&rsa_attrs, 3);
            if (ret != TEE_SUCCESS) {
              DMSG("Error");
            }

            // create your structures to de / encrypt
            to_encrypt = TEE_Malloc (in_len, 0);
            cipher = TEE_Malloc (cipher_len, 0);
            if (!to_encrypt || !cipher) {
              DMSG("Error");
            }
            
             DMSG("RSA Test Buffer");
            for(uint16_t y = 0; y < in_len; y += 8) {
		        DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", ((uint8_t *)dIn->buffer)[y], ((uint8_t *)dIn->buffer)[y+1], ((uint8_t *)dIn->buffer)[y+2], ((uint8_t *)dIn->buffer)[y+3], ((uint8_t *)dIn->buffer)[y+4], ((uint8_t *)dIn->buffer)[y+5], ((uint8_t *)dIn->buffer)[y+6], ((uint8_t *)dIn->buffer)[y+7]);
	        }

            TEE_MemMove(to_encrypt, dIn->buffer, in_len);

            // setup the info structure about the key
            TEE_GetObjectInfo(tee_key, &info);

            // Allocate the operation
            ret = TEE_AllocateOperation (&handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, info.maxObjectSize);
            if (ret != TEE_SUCCESS) {
              DMSG("Error");
            }

            // set the key
            ret = TEE_SetOperationKey(handle, tee_key);
            if (ret != TEE_SUCCESS) {
              TEE_FreeOperation(handle);
              DMSG("Error");
            }

            // encrypt
            ret = TEE_AsymmetricEncrypt (handle, (TEE_Attribute *)NULL, 0, to_encrypt, in_len, cipher, &cipher_len);
            if (ret != TEE_SUCCESS) {
              TEE_FreeOperation(handle);
              DMSG("Error");
            }

            DMSG("RSA Encrypted Buffer has %d Bytes", cipher_len);
            for(uint16_t y = 0; y < cipher_len; y += 8) {
		        DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", ((uint8_t *)cipher)[y], ((uint8_t *)cipher)[y+1], ((uint8_t *)cipher)[y+2], ((uint8_t *)cipher)[y+3], ((uint8_t *)cipher)[y+4], ((uint8_t *)cipher)[y+5], ((uint8_t *)cipher)[y+6], ((uint8_t *)cipher)[y+7]);
	        }
            TEE_MemMove(cOut->b.buffer, cipher, cipher_len);
            cOut->b.size = cipher_len;
            // clean up
            TEE_FreeOperation(handle);
            TEE_FreeTransientObject(tee_key);
            TEE_Free(cipher);
            TEE_Free(to_encrypt);
            DMSG("end of rsa encrypt");
        
        }
    }
Exit:
    return retVal;
}

//*** CryptRsaDecrypt()
// This is the entry point for decryption using RSA. Decryption is
// use of the private exponent. The "padType" parameter determines what
// padding was used.
//
//  return type:    TPM_RC
//      TPM_RC_SIZE        'cInSize' is not the same as the size of the public
//                          modulus of 'key'; or numeric value of the encrypted
//                          data is greater than the modulus
//      TPM_RC_VALUE       'dOutSize' is not large enough for the result
//      TPM_RC_SCHEME      'padType' is not supported
//
LIB_EXPORT TPM_RC
CryptRsaDecrypt(
    TPM2B               *dOut,          // OUT: the decrypted data
    TPM2B               *cIn,           // IN: the data to decrypt
    OBJECT              *key,           // IN: the key to use for decryption
    TPMT_RSA_DECRYPT    *scheme,        // IN: the padding scheme
    const TPM2B         *label          // IN: in case it is needed for the scheme
    )
{
    TPM_RC                 retVal;

    uint8_t useHACrypto = 1;
    // Make sure that the necessary parameters are provided
    pAssert(cIn != NULL && dOut != NULL && key != NULL);

    // Size is checked to make sure that the encrypted value is the right size
    if(cIn->size != key->publicArea.unique.rsa.t.size)
        ERROR_RETURN(TPM_RC_SIZE);

    TEST(scheme->scheme);

    // For others that do padding, do the decryption in place and then
    // go handle the decoding.
    if((!useHACrypto) || (scheme->scheme != ALG_RSAES_VALUE)) {  
        retVal = RSADP(cIn, key);
        if(retVal == TPM_RC_SUCCESS)
        {
            // Remove padding
            switch(scheme->scheme)
            {
                case ALG_NULL_VALUE:
                    if(dOut->size < cIn->size)
                        return TPM_RC_VALUE;
                    MemoryCopy2B(dOut, cIn, dOut->size);
                    break;
                case ALG_RSAES_VALUE:
                    retVal = RSAES_Decode(dOut, cIn);
                    break;
                case ALG_OAEP_VALUE:
                    DMSG("hi OAEP");
                    retVal = OaepDecode(dOut, scheme->details.oaep.hashAlg, label, cIn);
                    break;
                default:
                    retVal = TPM_RC_SCHEME;
                    break;
            }
        }
    } else {
        RSAInitializePrivate(cIn, key);
        // Maximum supported size for xilsecure hardware is 512 * 8 = 4096 Bits
        uint8_t *privateExponentBuffer = TEE_Malloc(512, 0);
        uint16_t new_size = 512;
        privateExponent_t *pExp = &key->privateExponent;
        BnToBytes((bigNum)&pExp->D, privateExponentBuffer, &new_size); 



        TEE_Result ret = TEE_SUCCESS; // return code        
        TEE_ObjectHandle tee_key = (TEE_ObjectHandle) NULL;
        TEE_Attribute rsa_attrs[3];
        void *decrypted = NULL;
        void *cipher = NULL;
        TEE_ObjectInfo info;
        TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
        uint16_t in_len = (uint16_t)cIn->size;

        // https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__11__1__6__PKCS____1__V1__5__RSA.html
        // According to this it should probably be k-11
        uint32_t cipher_len = 2*key->publicArea.unique.rsa.t.size;


        uint8_t public_key[3] = {0x01, 0x00, 0x01};

        
        // modulus
        rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
        rsa_attrs[0].content.ref.buffer = (uint8_t *)key->publicArea.unique.rsa.t.buffer;
        rsa_attrs[0].content.ref.length = (uint16_t)key->publicArea.unique.rsa.t.size;
        // Public key
        rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
        rsa_attrs[1].content.ref.buffer = public_key;
        rsa_attrs[1].content.ref.length = 3;
        // Private key
        rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
        rsa_attrs[2].content.ref.buffer = privateExponentBuffer;
        rsa_attrs[2].content.ref.length = new_size;
        
        DMSG("Setting key size to %d and message size to %d and output len to %d", (key->publicArea.unique.rsa.t.size * 8), in_len, cipher_len);
        // create a transient object
        ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, (key->publicArea.unique.rsa.t.size * 8), &tee_key);
        if (ret != TEE_SUCCESS) {
          DMSG("Error");
        }

        // populate the object with your keys
        ret = TEE_PopulateTransientObject(tee_key, (TEE_Attribute *)&rsa_attrs, 3);
        if (ret != TEE_SUCCESS) {
          DMSG("Error");
        }

        // create your structures to de / encrypt
        cipher = TEE_Malloc (in_len, 0);
        decrypted = TEE_Malloc (2*cipher_len, 0);
        if (!decrypted || !cipher) {
          DMSG("Error");
        }

        TEE_MemMove(cipher, (uint8_t *)(cIn->buffer), in_len);

        // setup the info structure about the key
        TEE_GetObjectInfo(tee_key, &info);

        // Allocate the operation
        ret = TEE_AllocateOperation (&handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, info.maxObjectSize);
        if (ret != TEE_SUCCESS) {
          DMSG("Error");
        }

        // set the key
        ret = TEE_SetOperationKey(handle, tee_key);
        if (ret != TEE_SUCCESS) {
          TEE_FreeOperation(handle);
          DMSG("Error");
        }
        // encrypt
        ret = TEE_AsymmetricDecrypt (handle, (TEE_Attribute *)NULL, 0, cipher, in_len, decrypted, &cipher_len);
        if (ret != TEE_SUCCESS) {
          TEE_FreeOperation(handle);
          DMSG("Error");
        }

        TEE_MemMove(dOut->buffer, decrypted, cipher_len);
        dOut->size = cipher_len;
        // clean up
        TEE_Free(privateExponentBuffer);
        TEE_FreeOperation(handle);
        TEE_FreeTransientObject(tee_key);
        TEE_Free(decrypted);
        TEE_Free(cipher);
        retVal = TPM_RC_SUCCESS;
        DMSG("end of rsa encrypt");
    }
Exit:
    return retVal;
}

//*** CryptRsaSign()
// This function is used to generate an RSA signature of the type indicated in
// 'scheme'.
//
//  return type: TPM_RC
//      TPM_RC_SCHEME       'scheme' or 'hashAlg' are not supported
//      TPM_RC_VALUE        'hInSize' does not match 'hashAlg' (for RSASSA)
//
LIB_EXPORT TPM_RC
CryptRsaSign(
    TPMT_SIGNATURE      *sigOut,
    OBJECT              *key,           // IN: key to use
    TPM2B_DIGEST        *hIn,           // IN: the digest to sign
    RAND_STATE          *rand           // IN: the random number generator
                                        //      to use (mostly for testing)
    )
{
    TPM_RC                retVal = TPM_RC_SUCCESS;
    UINT16                modSize;

    // parameter checks
    pAssert(sigOut != NULL && key != NULL && hIn != NULL);

    modSize = key->publicArea.unique.rsa.t.size;

    // for all non-null signatures, the size is the size of the key modulus
    sigOut->signature.rsapss.sig.t.size = modSize;

    TEST(sigOut->sigAlg);

    uint8_t useHACrypto = 0;

    if(!useHACrypto) {
        switch(sigOut->sigAlg)
        {
            case ALG_NULL_VALUE:
                sigOut->signature.rsapss.sig.t.size = 0;
                return TPM_RC_SUCCESS;
            case ALG_RSAPSS_VALUE:
                retVal = PssEncode(&sigOut->signature.rsapss.sig.b,
                                   sigOut->signature.rsapss.hash, &hIn->b, rand);
                break;
            case ALG_RSASSA_VALUE:
                retVal = RSASSA_Encode(&sigOut->signature.rsassa.sig.b,
                                       sigOut->signature.rsassa.hash, &hIn->b);
                break;
            default:
                retVal = TPM_RC_SCHEME;
        }
        if(retVal == TPM_RC_SUCCESS)
        {
            // Do the encryption using the private key
            retVal = RSADP(&sigOut->signature.rsapss.sig.b, key);
        }
    } else {
        retVal = TPM_RC_SUCCESS;


    }
    return retVal;
}

//*** CryptRsaValidateSignature()
// This function is used to validate an RSA signature. If the signature is valid
// TPM_RC_SUCCESS is returned. If the signature is not valid, TPM_RC_SIGNATURE is
// returned. Other return codes indicate either parameter problems or fatal errors.
//
// return type: TPM_RC
//      TPM_RC_SIGNATURE    the signature does not check
//      TPM_RC_SCHEME       unsupported scheme or hash algorithm
//
LIB_EXPORT TPM_RC
CryptRsaValidateSignature(
    TPMT_SIGNATURE  *sig,           // IN: signature
    OBJECT          *key,           // IN: public modulus
    TPM2B_DIGEST    *digest         // IN: The digest being validated
    )
{
    TPM_RC          retVal;
//
    // Fatal programming errors
    pAssert(key != NULL && sig != NULL && digest != NULL);
    switch(sig->sigAlg)
    {
        case ALG_RSAPSS_VALUE:
        case ALG_RSASSA_VALUE:
            break;
        default:
            return TPM_RC_SCHEME;
    }

    // Errors that might be caused by calling parameters
    if(sig->signature.rsassa.sig.t.size != key->publicArea.unique.rsa.t.size)
        ERROR_RETURN(TPM_RC_SIGNATURE);

    TEST(sig->sigAlg);

    // Decrypt the block
    retVal = RSAEP(&sig->signature.rsassa.sig.b, key);
    if(retVal == TPM_RC_SUCCESS)
    {
        switch(sig->sigAlg)
        {
            case ALG_RSAPSS_VALUE:
                retVal = PssDecode(sig->signature.any.hashAlg, &digest->b,
                                   &sig->signature.rsassa.sig.b);
                break;
            case ALG_RSASSA_VALUE:
                retVal = RSASSA_Decode(sig->signature.any.hashAlg, &digest->b,
                                       &sig->signature.rsassa.sig.b);
                break;
            default:
                return TPM_RC_SCHEME;
        }
    }
Exit:
    return (retVal != TPM_RC_SUCCESS) ? TPM_RC_SIGNATURE : TPM_RC_SUCCESS;
}

#if SIMULATION && USE_RSA_KEY_CACHE
extern int s_rsaKeyCacheEnabled;
int GetCachedRsaKey(OBJECT *key, RAND_STATE *rand);
#define GET_CACHED_KEY(key, rand)                       \
            (s_rsaKeyCacheEnabled && GetCachedRsaKey(key, rand))
#else
#define GET_CACHED_KEY(key, rand)
#endif

//*** CryptRsaGenerateKey()
// Generate an RSA key from a provided seed
/*(See part 1 specification)
//      The formulation is:
//          KDFa(hash, seed, label, Name, Counter, bits)
//      Where
//          hash        the nameAlg from the public template
//          seed        a seed (will be a primary seed for a primary key)
//          label       a distinguishing label including vendor ID and
//                      vendor-assigned part number for the TPM.
//          Name        the nameAlg from the template and the hash of the template
//                      using nameAlg.
//          Counter     a 32-bit integer that is incremented each time the KDF is
//                      called in order to produce a specific key. This value
//                      can be a 32-bit integer in host format and does not need
//                      to be put in canonical form.
//          bits        the number of bits needed for the key.
//  The following process is implemented to find a RSA key pair:
//  1. pick a random number with enough bits from KDFa as a prime candidate
//  2. set the first two significant bits and the least significant bit of the
//     prime candidate
//  3. check if the number is a prime. if not, pick another random number
//  4. Make sure the difference between the two primes are more than 2^104.
//     Otherwise, restart the process for the second prime
//  5. If the counter has reached its maximum but we still can not find a valid
//     RSA key pair, return an internal error. This is an artificial bound.
//     Other implementation may choose a smaller number to indicate how many
//     times they are willing to try.
*/
// return type: TPM_RC
//  TPM_RC_CANCELED     operation was canceled
//  TPM_RC_RANGE        public exponent is not supported
//  TPM_RC_VALUE        could not find a prime using the provided parameters
LIB_EXPORT TPM_RC
CryptRsaGenerateKey(
    OBJECT              *rsaKey,            // IN/OUT: The object structure in which
                                            //          the key is created.
    RAND_STATE          *rand               // IN: if not NULL, the deterministic
                                            //     RNG state
    )
{
    UINT32               i;
    BN_PRIME(bnP); // These four declarations initialize the number to 0
    BN_PRIME(bnQ);
    BN_RSA(bnD);
    BN_RSA(bnN);
    BN_WORD(bnE);
    UINT32               e;
    int                  keySizeInBits;
    TPMT_PUBLIC         *publicArea = &rsaKey->publicArea;
    TPMT_SENSITIVE      *sensitive = &rsaKey->sensitive;
    TPM_RC               retVal = TPM_RC_NO_RESULT;
//

// Need to make sure that the caller did not specify an exponent that is
// not supported
    e = publicArea->parameters.rsaDetail.exponent;
    if(e == 0)
        e = RSA_DEFAULT_PUBLIC_EXPONENT;
    if(e < 65537)
        ERROR_RETURN(TPM_RC_RANGE);
    if(e != RSA_DEFAULT_PUBLIC_EXPONENT && !IsPrimeInt(e))
        ERROR_RETURN(TPM_RC_RANGE);
    BnSetWord(bnE, e);
    // Check that e is prime
    // check for supported key size.
    keySizeInBits = publicArea->parameters.rsaDetail.keyBits;
    if(((keySizeInBits % 1024) != 0)
       || (keySizeInBits > MAX_RSA_KEY_BITS)  // this might be redundant, but...
       || (keySizeInBits == 0))
        ERROR_RETURN(TPM_RC_VALUE);

    // Set the prime size for instrumentation purposes
    INSTRUMENT_SET(PrimeIndex, PRIME_INDEX(keySizeInBits / 2));

#if SIMULATION && USE_RSA_KEY_CACHE
    if(GET_CACHED_KEY(rsaKey, rand))
        return TPM_RC_SUCCESS;
#endif

    // Make sure that key generation has been tested
    TEST(ALG_NULL_VALUE);

    // Need to initialize the privateExponent structure
    RsaInitializeExponent(&rsaKey->privateExponent);

    // The prime is computed in P. When a new prime is found, Q is checked to
    // see if it is zero.  If so, P is copied to Q and a new P is found.
    // When both P and Q are non-zero, the modulus and
    // private exponent are computed and a trial encryption/decryption is
    // performed.  If the encrypt/decrypt fails, assume that at least one of the
    // primes is composite. Since we don't know which one, set Q to zero and start
    // over and find a new pair of primes.

    for(i = 1; (retVal != TPM_RC_SUCCESS) && (i != 100); i++)
    {
        if(_plat__IsCanceled())
            ERROR_RETURN(TPM_RC_CANCELED);

        BnGeneratePrimeForRSA(bnP, keySizeInBits / 2, e, rand);
        INSTRUMENT_INC(PrimeCounts[PrimeIndex]);

        // If this is the second prime, make sure that it differs from the
        // first prime by at least 2^100
        if(BnEqualZero(bnQ))
        {
            // copy p to q and compute another prime in p
            BnCopy(bnQ, bnP);
            continue;
        }
        // Make sure that the difference is at least 100 bits. Need to do it this
        // way because the big numbers are only positive values
        if(BnUnsignedCmp(bnP, bnQ) < 0)
            BnSub(bnD, bnQ, bnP);
        else
            BnSub(bnD, bnP, bnQ);
        if(BnMsb(bnD) < 100)
            continue;

        //Form the public modulus and set the unique value
        BnMult(bnN, bnP, bnQ);
        BnTo2B(bnN, &publicArea->unique.rsa.b,
               (NUMBYTES)BITS_TO_BYTES(keySizeInBits));

        // And the  prime to the sensitive area
        BnTo2B(bnP, &sensitive->sensitive.rsa.b,
               (NUMBYTES)BITS_TO_BYTES(keySizeInBits) / 2);

        // Make sure everything came out right. The MSb of the values must be
        // one
        if(((publicArea->unique.rsa.t.buffer[0] & 0x80) == 0)
           || ((sensitive->sensitive.rsa.t.buffer[0] & 0x80) == 0))
            FAIL(FATAL_ERROR_INTERNAL);

        // Make sure that we can form the private exponent values
        if(ComputePrivateExponent(bnP, bnQ, bnE, bnN, &rsaKey->privateExponent)
           != TRUE)
        {
            // If ComputePrivateExponent could not find an inverse for
            // Q, then copy P and recompute P. This might
            // cause both to be recomputed if P is also zero
            if(BnEqualZero(bnQ))
                BnCopy(bnQ, bnP);
            continue;
        }
        retVal = TPM_RC_SUCCESS;
        // Do a trial encryption decryption if this is a signing key
        if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        {
            BN_RSA(temp1);
            BN_RSA(temp2);
            BnGenerateRandomInRange(temp1, bnN, rand);

            // Encrypt with public exponent...
            BnModExp(temp2, temp1, bnE, bnN);
            // ...  then decrypt with private exponent
            RsaPrivateKeyOp(temp2, bnN, bnP, &rsaKey->privateExponent);

            // If the starting and ending values are not the same,
            // start over )-;
            if(BnUnsignedCmp(temp2, temp1) != 0)
            {
                BnSetWord(bnQ, 0);
                retVal = TPM_RC_NO_RESULT;
            }
        }
    }
Exit:
    if(retVal == TPM_RC_SUCCESS)
        rsaKey->attributes.privateExp = SET;
    return retVal;
}

#endif // ALG_RSA
