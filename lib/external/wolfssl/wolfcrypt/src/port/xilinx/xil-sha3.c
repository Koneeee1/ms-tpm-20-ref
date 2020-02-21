/* xil-sha3.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

//#include <wolfssl/wolfcrypt/settings.h>


#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_XILINX_CRYPT_SHA)
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>


#if !defined(WOLFSSL_NOSHA3_224) || !defined(WOLFSSL_NOSHA3_256) \
    || !defined(WOLFSSL_NOSHA3_512)
    #error sizes of SHA3 other than 384 are not supported
#endif

#define LOCALDEBUG

// Some steps are not necessary using Xilinx HA, but they keep up with the interface implemented in wolfssl
/* Initialize hardware for SHA3 operations
 *
 * sha   SHA3 structure to initialize
 * heap  memory heap hint to use
 * devId used for async operations (currently not supported here)
 * operation handle for TEE Operation Specification
 */
int wc_InitSha3_384(wc_Sha3* sha, void* heap, int devId)
{
	int ret = 0;
    if (sha == NULL) {
        return BAD_FUNC_ARG;
    }
    sha->heap = heap;
    
    // Reset state data for each block 
    for (uint8_t i = 0; i < 25; i++) {
        sha->s[i] = 0;
    }
    
    // Place next message byte at index zero
    sha->i = 0;

    // Initialize operation handle
    sha->operation  = (TEE_OperationHandle)NULL;
    TEE_AllocateOperation(&sha->operation, TEE_ALG_SHA384, TEE_MODE_DIGEST, 0);

    #ifdef LOCALDEBUG
	DMSG("wc_InitSha3_384 sha->operation %x", sha->operation);
    #endif
    return ret;


}


/* Update SHA3 state
 *
 * sha   SHA3 structure to update
 * data  message to update SHA3 state with
 * len   length of data buffer
 */
int wc_Sha3_384_Update(wc_Sha3* sha, const byte* data, word32 len)
{
    if (sha == NULL ||  (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

    #ifdef LOCALDEBUG
	DMSG("wc_Sha3_384_Update with %x new Bytes", len);
    for(uint8_t y = 0; y < len; y += 8) {
		DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", data[y], data[y+1], data[y+2], data[y+3], data[y+4], data[y+5], data[y+6], data[y+7]);
	}
	#endif

    TEE_DigestUpdate(sha->operation, data, len);
    return 0;
}


/* Finalize SHA3 state and get digest
 *
 * sha  SHA3 structure to get hash
 * out  digest out, expected to be large enough to hold SHA3 digest
 */
int wc_Sha3_384_Final(wc_Sha3* sha, byte* out)
{
    if (sha == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    size_t hash_len = 48;

    // TEE expects data pointer in DoFinal call so we just give it empty data with length 0    

    void *null_ptr = NULL;
    TEE_DigestDoFinal(sha->operation, null_ptr, 0, out, &hash_len);
    
    #ifdef LOCALDEBUG	
    DMSG("wc_Sha3_384_Final creates digest");
    for(uint8_t y = 0; y < 48; y += 8) {
		DMSG("%02x%02x%02x%02x%02x%02x%02x%02x", out[y], out[y+1], out[y+2], out[y+3], out[y+4], out[y+5], out[y+6], out[y+7]);
	}
    #endif

    return 0;
}


/* Free SHA3 structure
 *
 * sha  SHA3 structure to free
 */
void wc_Sha3_384_Free(wc_Sha3* sha)
{
    TEE_FreeOperation(sha->operation);
    (void)sha;
    /* nothing to free yet */
}


/* Get SHA3 digest without finalize SHA3 state
 *
 * sha  SHA3 structure to get hash
 * out  digest out, expected to be large enough to hold SHA3 digest
 */
int wc_Sha3_384_GetHash(wc_Sha3* sha, byte* out)
{
    wc_Sha3 s;

    if (sha == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wc_Sha3_384_Copy(sha, &s) != 0) {
        WOLFSSL_MSG("Unable to copy SHA3 structure");
        return MEMORY_E;
    }

    return wc_Sha3_384_Final(&s, out);
}


/* Get copy of SHA3 structure
 *
 * src SHA3 structure to make copy of
 * dst [out]structure to hold copy
 */
int wc_Sha3_384_Copy(wc_Sha3* src, wc_Sha3* dst)
{
    if (src == NULL || dst== NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY((byte*)dst, (byte*)src, sizeof(wc_Sha3));
    return 0;
}

#endif
