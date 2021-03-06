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
// This file contains the implementation of the symmetric block cipher modes
// allowed for a TPM. These functions only use the single block encryption functions
// of the selected symmetric crypto library.

//** Includes, Defines, and Typedefs
#include "Tpm.h"
#include <string.h>
#include "CryptSym.h"
#include <utee_defines.h>
#include <arm_user_sysreg.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

//** Initialization and Data Access Functions
//
//*** CryptSymInit()
// This function is called to do _TPM_Init processing
BOOL
CryptSymInit(
    void
    )
{
    return TRUE;
}

//*** CryptSymStartup()
// This function is called to do TPM2_Startup() processing
BOOL
CryptSymStartup(
    void
    )
{
    return TRUE;
}

//*** CryptGetSymmetricBlockSize()
// This function returns the block size of the algorithm.
//  Return Type: INT16
//   <= 0     cipher not supported
//   > 0      the cipher block size in bytes
LIB_EXPORT INT16
CryptGetSymmetricBlockSize(
    TPM_ALG_ID      symmetricAlg,   // IN: the symmetric algorithm
    UINT16          keySizeInBits   // IN: the key size
    )
{
    switch(symmetricAlg)
    {
#if     ALG_AES
        case ALG_AES_VALUE:
            switch(keySizeInBits)
            {
                case 128:
                    return AES_128_BLOCK_SIZE_BYTES;
                case 192:
                    return AES_192_BLOCK_SIZE_BYTES;
                case 256:
                    return AES_256_BLOCK_SIZE_BYTES;
                default:
                    break;
            }
            break;
#endif
#if     ALG_SM4
        case ALG_SM4_VALUE:
            switch(keySizeInBits)
            {
                case 128:
                    return SM4_128_BLOCK_SIZE_BYTES;
                default:
                    break;
            }
#endif
#if     ALG_CAMELLIA
        case ALG_CAMELLIA_VALUE:
            switch(keySizeInBits)
            {
                case 128:
                    return CAMELLIA_128_BLOCK_SIZE_BYTES;
                case 192:
                    return CAMELLIA_192_BLOCK_SIZE_BYTES;
                case 256:
                    return CAMELLIA_256_BLOCK_SIZE_BYTES;
                default:
                    break;
            }
#endif
#if     ALG_TDES
        case ALG_TDES_VALUE:
            switch(keySizeInBits)
            {
                case 128:
                    return TDES_128_BLOCK_SIZE_BYTES;
                case 192:
                    return TDES_192_BLOCK_SIZE_BYTES;
                default:
                    break;
            }
#endif
        default:
            break;
    }
    return 0;
}

//** Symmetric Encryption
// This function performs symmetric encryption based on the mode.
//  Return Type: TPM_RC
//      TPM_RC_SIZE         'dSize' is not a multiple of the block size for an
//                          algorithm that requires it
//      TPM_RC_FAILURE      Fatal error
LIB_EXPORT TPM_RC
CryptSymmetricEncrypt(
    BYTE                *dOut,          // OUT:
    TPM_ALG_ID           algorithm,     // IN: the symmetric algorithm
    UINT16               keySizeInBits, // IN: key size in bits
    const BYTE          *key,           // IN: key buffer. The size of this buffer
                                        //     in bytes is (keySizeInBits + 7) / 8
    TPM2B_IV            *ivInOut,       // IN/OUT: IV for decryption.
    TPM_ALG_ID           mode,          // IN: Mode to use
    INT32                dSize,         // IN: data size (may need to be a
                                        //     multiple of the blockSize)
    const BYTE          *dIn            // IN: data buffer
    )
{
    BYTE                *pIv;
    int                  i;
    BYTE                 tmp[MAX_SYM_BLOCK_SIZE];
    BYTE                *pT;
    tpmCryptKeySchedule_t        keySchedule;
    INT16                blockSize;
    TpmCryptSetSymKeyCall_t        encrypt;
    BYTE                *iv;
    BYTE                 defaultIv[MAX_SYM_BLOCK_SIZE] = {0};
//

#ifdef TEEHACRYPTO
    uint8_t useHACrypto = 1;
#else
    uint8_t useHACrypto = 0;
#endif

    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    if(dSize == 0)
        return TPM_RC_SUCCESS;

    TEST(algorithm);
    blockSize = CryptGetSymmetricBlockSize(algorithm, keySizeInBits);
    if(blockSize == 0)
        return TPM_RC_FAILURE;
    // If the iv is provided, then it is expected to be block sized. In some cases,
    // the caller is providing an array of 0's that is equal to [MAX_SYM_BLOCK_SIZE]
    // with no knowledge of the actual block size. This function will set it.
    if((ivInOut != NULL) && (mode != ALG_ECB_VALUE))
    {
        ivInOut->t.size = blockSize;
        iv = ivInOut->t.buffer;
    }
    else
        iv = defaultIv;
    pIv = iv;

    // Create encrypt key schedule and set the encryption function pointer.

    SELECT(ENCRYPT);

    switch(mode)
    {
#if     ALG_CTR
        case ALG_CTR_VALUE: ;
#ifdef BENCHMARK
/*    uint64_t cntpct = read_cntpct();
    uint64_t cntfrq = read_cntfrq();
    uint64_t ptime_start = (cntpct * 1000000) / cntfrq;*/
    TEE_Time time_start;
    TEE_Time time_end;
    TEE_GetSystemTime(&time_start);
#endif

            // Xilinx requires 96 bit IV and 256 bit key
            // To encrypt / decrypt with 128 bit IV Value from CTR the last 4 bytes have to be 0x00, 0x00, 0x00, 0x02 and can then be safely ignored 
            if(keySizeInBits == 256 && ivInOut->t.buffer[12] == 0x00 && ivInOut->t.buffer[13] == 0x00 && ivInOut->t.buffer[14] == 0x00 && ivInOut->t.buffer[15] == 0x02 && useHACrypto) {
            uint8_t k[32], iv_b[64], tag[16];
            uint8_t t[16] = { 0 };
            uint8_t aad[32] = { 0 };
	        uint8_t p[128], c[64];
	        uint32_t k_len, p_len, aad_len, iv_len, c_len, t_len;
            k_len = 32;
            iv_len = 12;
            p_len = dSize;
            c_len = p_len;
            t_len = 16;
            memcpy(k, key, k_len);
            memcpy(iv_b, ivInOut->t.buffer, iv_len);
            memcpy(p, dIn, p_len);

            TEE_Result ret = TEE_SUCCESS;
            TEE_OperationHandle handle2 = (TEE_OperationHandle) NULL;
    TEE_ObjectHandle key_handle = (TEE_ObjectHandle) NULL;

    
    // Allocate the operation
    ret = TEE_AllocateOperation (&handle2, TEE_ALG_ZYNQMP_AES_GCM, TEE_MODE_ENCRYPT, 256);
    if (ret != TEE_SUCCESS) {
        DMSG("Error %x", ret);
    }
    // Allocate the key    
	ret = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_handle);
	if (ret != TEE_SUCCESS) {
        DMSG("Failed to allocate transient object");
	}
    TEE_Attribute aes_attr;

	TEE_InitRefAttribute(&aes_attr, TEE_ATTR_SECRET_VALUE, k, k_len);
    
    // Set key
    ret = TEE_PopulateTransientObject(key_handle, &aes_attr, 1);
    if (ret != TEE_SUCCESS) {
      DMSG("Error");
    }

    
	ret = TEE_SetOperationKey(handle2, key_handle);
	if (ret != TEE_SUCCESS) {
		DMSG("TEE_SetOperationKey failed %d", ret);
	}
		    /*
    DMSG(" IV len %d", iv_len);
for(uint8_t y = 0; y < iv_len; y += 8) {
	DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", iv_b[y], iv_b[y+1], iv_b[y+2], iv_b[y+3], iv_b[y+4], iv_b[y+5], iv_b[y+6], iv_b[y+7]);
	}*/
    
    ret = TEE_AEInit(handle2, iv_b, iv_len, t_len * 8, 0, 0);
    if (ret != TEE_SUCCESS) {
        TEE_FreeOperation(handle2);
        DMSG("Error AEInit %x", ret);
    }
    /*
    DMSG("AES In Data");
for(uint8_t y = 0; y < p_len; y += 8) {
		DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", p[y], p[y+1], p[y+2], p[y+3], p[y+4], p[y+5], p[y+6], p[y+7]);
	}
    */
    ret = TEE_AEEncryptFinal(handle2, p, p_len, c, &c_len, t, &t_len);
    if (ret != TEE_SUCCESS) {
        TEE_FreeOperation(handle2);
        DMSG("Error AEInit %x", ret);
    }
/*
    DMSG("AES Encrypted Buffer");
for(uint8_t y = 0; y < p_len; y += 8) {
		DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", c[y], c[y+1], c[y+2], c[y+3], c[y+4], c[y+5], c[y+6], c[y+7]);
	}
*/
    // Release the session resources
    if (key_handle != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(key_handle);
    }
    if (handle2 != TEE_HANDLE_NULL) {
        TEE_FreeOperation(handle2);
    }
    memcpy(dOut, c, c_len);
    
            } else {
                for(; dSize > 0; dSize -= blockSize)
                {
                    // Encrypt the current value of the IV(counter)
                    ENCRYPT(&keySchedule, iv, tmp);

                    //increment the counter (counter is big-endian so start at end)
                    for(i = blockSize - 1; i >= 0; i--)
                        if((iv[i] += 1) != 0)
                            break;

                    // XOR the encrypted counter value with input and put into output
                    pT = tmp;
                    for(i = (dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                        *dOut++ = *dIn++ ^ *pT++;
                }
            }
#ifdef BENCHMARK
/*           cntpct = read_cntpct();
            cntfrq = read_cntfrq();
            uint64_t ptime_end = (cntpct * 1000000) / cntfrq;
          DMSG("AESEncrypt took exactly %lld microseconds", (long long int)(ptime_end - ptime_start));*/
    TEE_GetSystemTime(&time_end);
DMSG("Aes_Encrypt took %" PRIu64 " microseconds", (time_end.micros - time_start.micros));
#endif
            break;
#endif
#if     ALG_OFB
        case ALG_OFB_VALUE:
            // This is written so that dIn and dOut may be the same
            for(; dSize > 0; dSize -= blockSize)
            {
                // Encrypt the current value of the "IV"
                ENCRYPT(&keySchedule, iv, iv);

                // XOR the encrypted IV into dIn to create the cipher text (dOut)
                pIv = iv;
                for(i = (dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                    *dOut++ = (*pIv++ ^ *dIn++);
            }
            break;
#endif
#if     ALG_CBC
        case ALG_CBC_VALUE:
            // For CBC the data size must be an even multiple of the
            // cipher block size
            if((dSize % blockSize) != 0)
                return TPM_RC_SIZE;
            // XOR the data block into the IV, encrypt the IV into the IV
            // and then copy the IV to the output
            for(; dSize > 0; dSize -= blockSize)
            {
                pIv = iv;
                for(i = blockSize; i > 0; i--)
                    *pIv++ ^= *dIn++;
                ENCRYPT(&keySchedule, iv, iv);
                pIv = iv;
                for(i = blockSize; i > 0; i--)
                    *dOut++ = *pIv++;
            }
            break;
#endif
        // CFB is not optional
        case ALG_CFB_VALUE:
            // Encrypt the IV into the IV, XOR in the data, and copy to output
            for(; dSize > 0; dSize -= blockSize)
            {
                // Encrypt the current value of the IV
                ENCRYPT(&keySchedule, iv, iv);
                pIv = iv;
                for(i = (int)(dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                    // XOR the data into the IV to create the cipher text
                    // and put into the output
                    *dOut++ = *pIv++ ^= *dIn++;
            }
            // If the inner loop (i loop) was smaller than blockSize, then dSize
            // would have been smaller than blockSize and it is now negative. If
            // it is negative, then it indicates how many bytes are needed to pad
            // out the IV for the next round.
            for(; dSize < 0; dSize++)
                *pIv++ = 0;
            break;
#if     ALG_ECB
        case ALG_ECB_VALUE:
            // For ECB the data size must be an even multiple of the
            // cipher block size
            if((dSize % blockSize) != 0)
                return TPM_RC_SIZE;
            // Encrypt the input block to the output block
            for(; dSize > 0; dSize -= blockSize)
            {
                ENCRYPT(&keySchedule, dIn, dOut);
                dIn = &dIn[blockSize];
                dOut = &dOut[blockSize];
            }
            break;
#endif
        default:
            return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

//*** CryptSymmetricDecrypt()
// This function performs symmetric decryption based on the mode.
//  Return Type: TPM_RC
//      TPM_RC_FAILURE      A fatal error
//      TPM_RCS_SIZE        'dSize' is not a multiple of the block size for an
//                          algorithm that requires it
LIB_EXPORT TPM_RC
CryptSymmetricDecrypt(
    BYTE                *dOut,          // OUT: decrypted data
    TPM_ALG_ID           algorithm,     // IN: the symmetric algorithm
    UINT16               keySizeInBits, // IN: key size in bits
    const BYTE          *key,           // IN: key buffer. The size of this buffer
                                        //     in bytes is (keySizeInBits + 7) / 8
    TPM2B_IV            *ivInOut,       // IN/OUT: IV for decryption.
    TPM_ALG_ID           mode,          // IN: Mode to use
    INT32                dSize,         // IN: data size (may need to be a
                                        //     multiple of the blockSize)
    const BYTE          *dIn            // IN: data buffer
    )
{
    BYTE                *pIv;
    int                  i;
    BYTE                 tmp[MAX_SYM_BLOCK_SIZE];
    BYTE                *pT;
    tpmCryptKeySchedule_t        keySchedule;
    INT16                blockSize;
    BYTE                *iv;
    TpmCryptSetSymKeyCall_t        encrypt;
    TpmCryptSetSymKeyCall_t        decrypt;
    BYTE                 defaultIv[MAX_SYM_BLOCK_SIZE] = {0};

#ifdef TEEHACRYPTO
    uint8_t useHACrypto = 1;
#else
    uint8_t useHACrypto = 0;
#endif

    // These are used but the compiler can't tell because they are initialized
    // in case statements and it can't tell if they are always initialized
    // when needed, so... Comment these out if the compiler can tell or doesn't
    // care that these are initialized before use.
    encrypt = NULL;
    decrypt = NULL;

    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    if(dSize == 0)
        return TPM_RC_SUCCESS;

    TEST(algorithm);
    blockSize = CryptGetSymmetricBlockSize(algorithm, keySizeInBits);
    if(blockSize == 0)
        return TPM_RC_FAILURE;
    // If the iv is provided, then it is expected to be block sized. In some cases,
    // the caller is providing an array of 0's that is equal to [MAX_SYM_BLOCK_SIZE]
    // with no knowledge of the actual block size. This function will set it.
    if((ivInOut != NULL) && (mode != ALG_ECB_VALUE))
    {
        ivInOut->t.size = blockSize;
        iv = ivInOut->t.buffer;
    }
    else
        iv = defaultIv;

    pIv = iv;
    // Use the mode to select the key schedule to create. Encrypt always uses the
    // encryption schedule. Depending on the mode, decryption might use either
    // the decryption or encryption schedule.
    switch(mode)
    {
#if ALG_CBC || ALG_ECB
        case ALG_CBC_VALUE: // decrypt = decrypt
        case ALG_ECB_VALUE:
            // For ECB and CBC, the data size must be an even multiple of the
            // cipher block size
            if((dSize % blockSize) != 0)
                return TPM_RC_SIZE;
            SELECT(DECRYPT);
            break;
#endif
        default:
            // For the remaining stream ciphers, use encryption to decrypt
            SELECT(ENCRYPT);
            break;
    }
    // Now do the mode-dependent decryption
    switch(mode)
    {
#if     ALG_CBC
        case ALG_CBC_VALUE:
            // Copy the input data to a temp buffer, decrypt the buffer into the
            // output, XOR in the IV, and copy the temp buffer to the IV and repeat.
            for(; dSize > 0; dSize -= blockSize)
            {
                pT = tmp;
                for(i = blockSize; i > 0; i--)
                    *pT++ = *dIn++;
                DECRYPT(&keySchedule, tmp, dOut);
                pIv = iv;
                pT = tmp;
                for(i = blockSize; i > 0; i--)
                {
                    *dOut++ ^= *pIv;
                    *pIv++ = *pT++;
                }
            }
            break;
#endif
        case ALG_CFB_VALUE:
            for(; dSize > 0; dSize -= blockSize)
            {
                // Encrypt the IV into the temp buffer
                ENCRYPT(&keySchedule, iv, tmp);
                pT = tmp;
                pIv = iv;
                for(i = (dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                    // Copy the current cipher text to IV, XOR
                    // with the temp buffer and put into the output
                    *dOut++ = *pT++ ^ (*pIv++ = *dIn++);
            }
            // If the inner loop (i loop) was smaller than blockSize, then dSize
            // would have been smaller than blockSize and it is now negative
            // If it is negative, then it indicates how may fill bytes
            // are needed to pad out the IV for the next round.
            for(; dSize < 0; dSize++)
                *pIv++ = 0;

            break;
#if     ALG_CTR
        case ALG_CTR_VALUE: ;
#ifdef BENCHMARK
/*            uint64_t cntpct = read_cntpct();
            uint64_t cntfrq = read_cntfrq();
            uint64_t ptime_start = (cntpct * 1000000) / cntfrq;*/
    TEE_Time time_start;
    TEE_Time time_end;
    TEE_GetSystemTime(&time_start);
#endif

            // Xilinx requires 96 bit IV and 256 bit key
            // To encrypt / decrypt with 128 bit IV Value from CTR the last 4 bytes have to be 0x00, 0x00, 0x00, 0x02 and can then be safely ignored 
            if(keySizeInBits == 256 && ivInOut->t.buffer[12] == 0x00 && ivInOut->t.buffer[13] == 0x00 && ivInOut->t.buffer[14] == 0x00 && ivInOut->t.buffer[15] == 0x02 && useHACrypto) {
            uint8_t k[32], iv_b[64], tag[16];
            uint8_t t[16] = { 0 };
            uint8_t aad[32] = { 0 };
	        uint8_t p[128], c[64];
	        uint32_t k_len, p_len, aad_len, iv_len, c_len, t_len;
            k_len = 32;
            iv_len = 12;
            p_len = dSize;
            c_len = p_len;
            t_len = 16;
            memcpy(k, key, k_len);
            memcpy(iv_b, ivInOut->t.buffer, iv_len);
            memcpy(p, dIn, p_len);


            TEE_Result ret = TEE_SUCCESS;
            TEE_OperationHandle handle2 = (TEE_OperationHandle) NULL;
            TEE_ObjectHandle key_handle = (TEE_ObjectHandle) NULL;

            
            // Allocate the operation
            ret = TEE_AllocateOperation (&handle2, TEE_ALG_ZYNQMP_AES_GCM, TEE_MODE_ENCRYPT, 256);
            if (ret != TEE_SUCCESS) {
                DMSG("Error %x", ret);
            }
            // Allocate the key    
	        ret = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_handle);
	        if (ret != TEE_SUCCESS) {
                DMSG("Failed to allocate transient object");
	        }
            TEE_Attribute aes_attr;

	        TEE_InitRefAttribute(&aes_attr, TEE_ATTR_SECRET_VALUE, k, k_len);
            
            // Set key
            ret = TEE_PopulateTransientObject(key_handle, &aes_attr, 1);
            if (ret != TEE_SUCCESS) {
              DMSG("Error");
            }
            

            
	        ret = TEE_SetOperationKey(handle2, key_handle);
	        if (ret != TEE_SUCCESS) {
		        DMSG("TEE_SetOperationKey failed %d", ret);
	        }
		    /*
            DMSG("IV len %d", iv_len);
        for(uint8_t y = 0; y < iv_len; y += 8) {
	        DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", iv_b[y], iv_b[y+1], iv_b[y+2], iv_b[y+3], iv_b[y+4], iv_b[y+5], iv_b[y+6], iv_b[y+7]);
	        }*/
            
            ret = TEE_AEInit(handle2, iv_b, iv_len, t_len * 8, 0, 0);
            if (ret != TEE_SUCCESS) {
                TEE_FreeOperation(handle2);
                DMSG("Error AEInit %x", ret);
            }
            
/*
            DMSG("AES In Data");
        for(uint8_t y = 0; y < p_len; y += 8) {
		        DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", p[y], p[y+1], p[y+2], p[y+3], p[y+4], p[y+5], p[y+6], p[y+7]);
	        } */
            ret = TEE_AEEncryptFinal(handle2, p, p_len, c, &c_len, t, &t_len);
            if (ret != TEE_SUCCESS) {
                TEE_FreeOperation(handle2);
                DMSG("Error AEInit %x", ret);
            }
/*
            DMSG("AES Encrypted Buffer");
        for(uint8_t y = 0; y < p_len; y += 8) {
		        DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", c[y], c[y+1], c[y+2], c[y+3], c[y+4], c[y+5], c[y+6], c[y+7]);
	        }
*/

	    // Release the session resources
	    if (key_handle != TEE_HANDLE_NULL) {
		TEE_FreeTransientObject(key_handle);
	    }
	    if (handle2 != TEE_HANDLE_NULL) {
		TEE_FreeOperation(handle2);
	    }
            memcpy(dOut, c, c_len);
    
            } else {
                for(; dSize > 0; dSize -= blockSize)
                {
                    // Encrypt the current value of the IV(counter)
                    ENCRYPT(&keySchedule, iv, tmp);

                    //increment the counter (counter is big-endian so start at end)
                    for(i = blockSize - 1; i >= 0; i--)
                        if((iv[i] += 1) != 0)
                            break;
                    // XOR the encrypted counter value with input and put into output
                    pT = tmp;
                    for(i = (dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                        *dOut++ = *dIn++ ^ *pT++;
                }
            }
#ifdef BENCHMARK
/*    cntpct = read_cntpct();
    cntfrq = read_cntfrq();
    uint64_t ptime_end = (cntpct * 1000000) / cntfrq;
  DMSG("AESDecrypt took exactly %lld microseconds", (long long int)(ptime_end - ptime_start));*/
    TEE_GetSystemTime(&time_end);
    DMSG("AesDecrypt took %" PRIu64 " microseconds", (time_end.micros - time_start.micros));
#endif
            break;
#endif
#if     ALG_ECB
        case ALG_ECB_VALUE:
            for(; dSize > 0; dSize -= blockSize)
            {
                DECRYPT(&keySchedule, dIn, dOut);
                dIn = &dIn[blockSize];
                dOut = &dOut[blockSize];
            }
            break;
#endif
#if     ALG_OFB
        case ALG_OFB_VALUE:
            // This is written so that dIn and dOut may be the same
            for(; dSize > 0; dSize -= blockSize)
            {
                // Encrypt the current value of the "IV"
                ENCRYPT(&keySchedule, iv, iv);

                // XOR the encrypted IV into dIn to create the cipher text (dOut)
                pIv = iv;
                for(i = (dSize < blockSize) ? dSize : blockSize; i > 0; i--)
                    *dOut++ = (*pIv++ ^ *dIn++);
            }
            break;
#endif
        default:
            return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

//*** CryptSymKeyValidate()
// Validate that a provided symmetric key meets the requirements of the TPM
//  Return Type: TPM_RC
//      TPM_RC_KEY_SIZE         Key size specifiers do not match
//      TPM_RC_KEY              Key is not allowed
TPM_RC
CryptSymKeyValidate(
    TPMT_SYM_DEF_OBJECT *symDef,
    TPM2B_SYM_KEY       *key
    )
{
    if(key->t.size != BITS_TO_BYTES(symDef->keyBits.sym))
        return TPM_RCS_KEY_SIZE;
#if     ALG_TDES
    if(symDef->algorithm == TPM_ALG_TDES && !CryptDesValidateKey(key))
        return TPM_RCS_KEY;
#endif // ALG_TDES
    return TPM_RC_SUCCESS;
}



