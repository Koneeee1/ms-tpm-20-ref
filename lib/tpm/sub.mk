FTPM_FLAGS = -DGCC -DUSE_WOLFCRYPT -DSIMULATION=NO -DUSE_PLATFORM_EPS -DVTPM
FTPM_DEBUG =  -DCOMPILER_CHECKS=YES -DfTPMDebug -DRUNTIME_SIZE_CHECKS -DLIBRARY_COMPATIBILITY_CHECK
FTPM_RELEASE = -DCOMPILER_CHECKS=NO -DRUNTIME_SIZE_CHECKS=NO -DLIBRARY_COMPATIBILITY_CHECK=NO

#
# The fTPM needs to overwrite some of the header files used in the reference implementation. The search order GCC
# uses is dependent on the order the '-I/include/path' arguments are passed in. This is depended on the optee_os build
# system which makes it brittle. Force including these files here will make sure the correct files are used first.
#

FTPM_INCLUDES = -include ./reference/include/VendorString.h -include ./reference/include/Implementation.h

#
# The TPM causes a few warnings when compiled with GCC which are not critical.
#

FTPM_WARNING_SUPPRESS = -Wno-cast-align \
			-Wno-cast-function-type \
			-Wno-implicit-fallthrough \
			-Wno-missing-braces \
			-Wno-sign-compare \
			-Wno-suggest-attribute=noreturn \
			-Wno-switch-default

cflags-y += $(FTPM_FLAGS) $(WOLF_SSL_FLAGS) $(FTPM_INCLUDES) $(FTPM_WARNING_SUPPRESS)

#ifeq ($(CFG_TA_DEBUG),y)
cflags-y += $(FTPM_DEBUG)
#else
#cflags-y += $(FTPM_RELEASE)
#endif

global-incdirs-y += TPMCmd/tpm/include
global-incdirs-y += TPMCmd/tpm/include/ltc
global-incdirs-y += TPMCmd/tpm/include/prototypes
global-incdirs-y += TPMCmd/tpm/include/wolf

#
# Generated in WSL using:
# find -name *.c | while read line; do echo XXXX$line; done | sed -e 's/XXXX.\//srcs-y += TPMCmd/tpm/src//g'
# This may need to be updated if there are any changes to the reference implementation.
#

srcs-y += TPMCmd/tpm/src/command/Asymmetric/ECC_Parameters.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/ECDH_KeyGen.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/ECDH_ZGen.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/EC_Ephemeral.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/RSA_Decrypt.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/RSA_Encrypt.c
srcs-y += TPMCmd/tpm/src/command/Asymmetric/ZGen_2Phase.c
srcs-y += TPMCmd/tpm/src/command/AttachedComponent/AC_GetCapability.c
srcs-y += TPMCmd/tpm/src/command/AttachedComponent/AC_Send.c
srcs-y += TPMCmd/tpm/src/command/AttachedComponent/AC_spt.c
srcs-y += TPMCmd/tpm/src/command/AttachedComponent/Policy_AC_SendSelect.c
srcs-y += TPMCmd/tpm/src/command/Attestation/Attest_spt.c
srcs-y += TPMCmd/tpm/src/command/Attestation/Certify.c
srcs-y += TPMCmd/tpm/src/command/Attestation/CertifyCreation.c
srcs-y += TPMCmd/tpm/src/command/Attestation/GetCommandAuditDigest.c
srcs-y += TPMCmd/tpm/src/command/Attestation/GetSessionAuditDigest.c
srcs-y += TPMCmd/tpm/src/command/Attestation/GetTime.c
srcs-y += TPMCmd/tpm/src/command/Attestation/Quote.c
srcs-y += TPMCmd/tpm/src/command/Capability/GetCapability.c
srcs-y += TPMCmd/tpm/src/command/Capability/TestParms.c
srcs-y += TPMCmd/tpm/src/command/ClockTimer/ClockRateAdjust.c
srcs-y += TPMCmd/tpm/src/command/ClockTimer/ClockSet.c
srcs-y += TPMCmd/tpm/src/command/ClockTimer/ReadClock.c
srcs-y += TPMCmd/tpm/src/command/CommandAudit/SetCommandCodeAuditStatus.c
srcs-y += TPMCmd/tpm/src/command/Context/ContextLoad.c
srcs-y += TPMCmd/tpm/src/command/Context/ContextSave.c
srcs-y += TPMCmd/tpm/src/command/Context/Context_spt.c
srcs-y += TPMCmd/tpm/src/command/Context/EvictControl.c
srcs-y += TPMCmd/tpm/src/command/Context/FlushContext.c
srcs-y += TPMCmd/tpm/src/command/DA/DictionaryAttackLockReset.c
srcs-y += TPMCmd/tpm/src/command/DA/DictionaryAttackParameters.c
srcs-y += TPMCmd/tpm/src/command/Duplication/Duplicate.c
srcs-y += TPMCmd/tpm/src/command/Duplication/Import.c
srcs-y += TPMCmd/tpm/src/command/Duplication/Rewrap.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyAuthorize.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyAuthorizeNV.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyAuthValue.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyCommandCode.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyCounterTimer.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyCpHash.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyDuplicationSelect.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyGetDigest.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyLocality.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyNameHash.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyNV.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyNvWritten.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyOR.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyPassword.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyPCR.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyPhysicalPresence.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicySecret.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicySigned.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyTemplate.c
srcs-y += TPMCmd/tpm/src/command/EA/PolicyTicket.c
srcs-y += TPMCmd/tpm/src/command/EA/Policy_spt.c
srcs-y += TPMCmd/tpm/src/command/Ecdaa/Commit.c
srcs-y += TPMCmd/tpm/src/command/FieldUpgrade/FieldUpgradeData.c
srcs-y += TPMCmd/tpm/src/command/FieldUpgrade/FieldUpgradeStart.c
srcs-y += TPMCmd/tpm/src/command/FieldUpgrade/FirmwareRead.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/EventSequenceComplete.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/HashSequenceStart.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/HMAC_Start.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/MAC_Start.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/SequenceComplete.c
srcs-y += TPMCmd/tpm/src/command/HashHMAC/SequenceUpdate.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/ChangeEPS.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/ChangePPS.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/Clear.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/ClearControl.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/CreatePrimary.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/HierarchyChangeAuth.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/HierarchyControl.c
srcs-y += TPMCmd/tpm/src/command/Hierarchy/SetPrimaryPolicy.c
srcs-y += TPMCmd/tpm/src/command/Misc/PP_Commands.c
srcs-y += TPMCmd/tpm/src/command/Misc/SetAlgorithmSet.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_Certify.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_ChangeAuth.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_DefineSpace.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_Extend.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_GlobalWriteLock.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_Increment.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_Read.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_ReadLock.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_ReadPublic.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_SetBits.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_spt.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_UndefineSpace.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_UndefineSpaceSpecial.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_Write.c
srcs-y += TPMCmd/tpm/src/command/NVStorage/NV_WriteLock.c
srcs-y += TPMCmd/tpm/src/command/Object/ActivateCredential.c
srcs-y += TPMCmd/tpm/src/command/Object/Create.c
srcs-y += TPMCmd/tpm/src/command/Object/CreateLoaded.c
srcs-y += TPMCmd/tpm/src/command/Object/Load.c
srcs-y += TPMCmd/tpm/src/command/Object/LoadExternal.c
srcs-y += TPMCmd/tpm/src/command/Object/MakeCredential.c
srcs-y += TPMCmd/tpm/src/command/Object/ObjectChangeAuth.c
srcs-y += TPMCmd/tpm/src/command/Object/Object_spt.c
srcs-y += TPMCmd/tpm/src/command/Object/ReadPublic.c
srcs-y += TPMCmd/tpm/src/command/Object/Unseal.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_Allocate.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_Event.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_Extend.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_Read.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_Reset.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_SetAuthPolicy.c
srcs-y += TPMCmd/tpm/src/command/PCR/PCR_SetAuthValue.c
srcs-y += TPMCmd/tpm/src/command/Random/GetRandom.c
srcs-y += TPMCmd/tpm/src/command/Random/StirRandom.c
srcs-y += TPMCmd/tpm/src/command/Session/PolicyRestart.c
srcs-y += TPMCmd/tpm/src/command/Session/StartAuthSession.c
srcs-y += TPMCmd/tpm/src/command/Signature/Sign.c
srcs-y += TPMCmd/tpm/src/command/Signature/VerifySignature.c
srcs-y += TPMCmd/tpm/src/command/Startup/Shutdown.c
srcs-y += TPMCmd/tpm/src/command/Startup/Startup.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/EncryptDecrypt.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/EncryptDecrypt2.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/EncryptDecrypt_spt.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/Hash.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/HMAC.c
srcs-y += TPMCmd/tpm/src/command/Symmetric/MAC.c
srcs-y += TPMCmd/tpm/src/command/Testing/GetTestResult.c
srcs-y += TPMCmd/tpm/src/command/Testing/IncrementalSelfTest.c
srcs-y += TPMCmd/tpm/src/command/Testing/SelfTest.c
srcs-y += TPMCmd/tpm/src/command/Vendor/Vendor_TCG_Test.c
srcs-y += TPMCmd/tpm/src/crypt/AlgorithmTests.c
srcs-y += TPMCmd/tpm/src/crypt/BnConvert.c
srcs-y += TPMCmd/tpm/src/crypt/BnMath.c
srcs-y += TPMCmd/tpm/src/crypt/BnMemory.c
srcs-y += TPMCmd/tpm/src/crypt/CryptCmac.c
srcs-y += TPMCmd/tpm/src/crypt/CryptDes.c
srcs-y += TPMCmd/tpm/src/crypt/CryptEccData.c
srcs-y += TPMCmd/tpm/src/crypt/CryptEccKeyExchange.c
srcs-y += TPMCmd/tpm/src/crypt/CryptEccMain.c
srcs-y += TPMCmd/tpm/src/crypt/CryptEccSignature.c
srcs-y += TPMCmd/tpm/src/crypt/CryptHash.c
srcs-y += TPMCmd/tpm/src/crypt/CryptHashData.c
srcs-y += TPMCmd/tpm/src/crypt/CryptPrime.c
srcs-y += TPMCmd/tpm/src/crypt/CryptPrimeSieve.c
srcs-y += TPMCmd/tpm/src/crypt/CryptRand.c
srcs-y += TPMCmd/tpm/src/crypt/CryptRsa.c
srcs-y += TPMCmd/tpm/src/crypt/CryptSelfTest.c
srcs-y += TPMCmd/tpm/src/crypt/CryptSmac.c
srcs-y += TPMCmd/tpm/src/crypt/CryptSym.c
srcs-y += TPMCmd/tpm/src/crypt/CryptUtil.c
srcs-y += TPMCmd/tpm/src/crypt/ltc/TpmToLtcDesSupport.c
srcs-y += TPMCmd/tpm/src/crypt/ltc/TpmToLtcMath.c
srcs-y += TPMCmd/tpm/src/crypt/ltc/TpmToLtcSupport.c
srcs-y += TPMCmd/tpm/src/crypt/ossl/TpmToOsslDesSupport.c
srcs-y += TPMCmd/tpm/src/crypt/ossl/TpmToOsslMath.c
srcs-y += TPMCmd/tpm/src/crypt/ossl/TpmToOsslSupport.c
srcs-y += TPMCmd/tpm/src/crypt/PrimeData.c
srcs-y += TPMCmd/tpm/src/crypt/RsaKeyCache.c
srcs-y += TPMCmd/tpm/src/crypt/Ticket.c
srcs-y += TPMCmd/tpm/src/crypt/wolf/TpmToWolfDesSupport.c
srcs-y += TPMCmd/tpm/src/crypt/wolf/TpmToWolfMath.c
srcs-y += TPMCmd/tpm/src/crypt/wolf/TpmToWolfSupport.c
srcs-y += TPMCmd/tpm/src/events/_TPM_Hash_Data.c
srcs-y += TPMCmd/tpm/src/events/_TPM_Hash_End.c
srcs-y += TPMCmd/tpm/src/events/_TPM_Hash_Start.c
srcs-y += TPMCmd/tpm/src/events/_TPM_Init.c
srcs-y += TPMCmd/tpm/src/main/CommandDispatcher.c
srcs-y += TPMCmd/tpm/src/main/ExecCommand.c
srcs-y += TPMCmd/tpm/src/main/SessionProcess.c
srcs-y += TPMCmd/tpm/src/subsystem/CommandAudit.c
srcs-y += TPMCmd/tpm/src/subsystem/DA.c
srcs-y += TPMCmd/tpm/src/subsystem/Hierarchy.c
srcs-y += TPMCmd/tpm/src/subsystem/NvDynamic.c
srcs-y += TPMCmd/tpm/src/subsystem/NvReserved.c
srcs-y += TPMCmd/tpm/src/subsystem/Object.c
srcs-y += TPMCmd/tpm/src/subsystem/PCR.c
srcs-y += TPMCmd/tpm/src/subsystem/PP.c
srcs-y += TPMCmd/tpm/src/subsystem/Session.c
srcs-y += TPMCmd/tpm/src/subsystem/Time.c
srcs-y += TPMCmd/tpm/src/support/AlgorithmCap.c
srcs-y += TPMCmd/tpm/src/support/Bits.c
srcs-y += TPMCmd/tpm/src/support/CommandCodeAttributes.c
srcs-y += TPMCmd/tpm/src/support/Entity.c
srcs-y += TPMCmd/tpm/src/support/Global.c
srcs-y += TPMCmd/tpm/src/support/Handle.c
srcs-y += TPMCmd/tpm/src/support/IoBuffers.c
srcs-y += TPMCmd/tpm/src/support/Locality.c
srcs-y += TPMCmd/tpm/src/support/Manufacture.c
srcs-y += TPMCmd/tpm/src/support/Marshal.c
srcs-y += TPMCmd/tpm/src/support/MathOnByteBuffers.c
srcs-y += TPMCmd/tpm/src/support/Memory.c
srcs-y += TPMCmd/tpm/src/support/Power.c
srcs-y += TPMCmd/tpm/src/support/PropertyCap.c
srcs-y += TPMCmd/tpm/src/support/Response.c
srcs-y += TPMCmd/tpm/src/support/ResponseCodeProcessing.c
srcs-y += TPMCmd/tpm/src/support/TpmFail.c
srcs-y += TPMCmd/tpm/src/support/TpmSizeChecks.c
