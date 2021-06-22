#ifndef MBED_OS_PLATFORM_SECURE_FLASH_TRANSPORT_LAYER_SF_LIB_INCLUDE_SECUREFLASH_ENCRYPTION_ALG_H_
#define MBED_OS_PLATFORM_SECURE_FLASH_TRANSPORT_LAYER_SF_LIB_INCLUDE_SECUREFLASH_ENCRYPTION_ALG_H_

typedef enum {
	NO_AUTHEN,
	AUTHEN_WITH_DATA,
	AUTHEN_WITHOUT_DATA,
} AuthenRequirementEnum;

typedef enum {
	OP_NO_SECURITY_OPERATION,

	OP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV,
	OP_AUTHEN_TAG_DECRYPT_DATA,
	OP_AUTHEN_TAG_ENC_IV,
	OP_AUTHEN_TAG,
	OP_DECRYPT_DATA_ENC_IV,	
	OP_DECRYPT_DATA,

	OP_ENCRYPT_TAG_DATA_ENC_IV,
	OP_ENCRYPT_TAG_DATA,	
	OP_ENCRYPT_TAG_ENC_IV,
	OP_ENCRYPT_TAG,	
	OP_ENCRYPT_DATA_ENC_IV,	
	OP_ENCRYPT_DATA,

	OP_SIGNATURE_SIGN,
	OP_SIGNATURE_VERIFY,

}EncryptionOperationEnum;

/* authentication algorithm */
typedef enum {
	AUTHEN_NOT_SUP,
	AUTHEN_HMAC_SHA_1,
	AUTHEN_HMAC_SHA_256,
	AUTHEN_HMAC_SHA_384,
	AUTHEN_HMAC_SHA_512,
	AUTHEN_AES_CMAC_128,
	AUTHEN_AES_CMAC_256,
	AUTHEN_AES_GMAC_128,
	AUTHEN_AES_GMAC_256,
	AUTHEN_AES_CCM_128,
	AUTHEN_AES_CCM_192,
	AUTHEN_AES_CCM_256,
	AUTHEN_AES_GCM_128,
	AUTHEN_AES_GCM_192,
	AUTHEN_AES_GCM_256,
}AuthenEnum;

/* message encryption algorithm */
typedef enum {
	ALG_NONE,
	ALG_HMAC_SHA_1,
	ALG_HMAC_SHA_256,
	ALG_HMAC_SHA_384,
	ALG_HMAC_SHA_512,
	ALG_AES_CCM_128,
	ALG_AES_CCM_192,
	ALG_AES_CCM_256,
	ALG_AES_GCM_128,
	ALG_AES_GCM_192,
	ALG_AES_GCM_256,
	ALG_AES_ECB_128,
	ALG_AES_ECB_192,
	ALG_AES_ECB_256,
	ALG_AES_CBC_128,
	ALG_AES_CBC_192,
	ALG_AES_CBC_256,
	ALG_AES_OFB_128,
	ALG_AES_OFB_192,
	ALG_AES_OFB_256,
	ALG_AES_CTR_128,
	ALG_AES_CTR_192,
	ALG_AES_CTR_256,

	ALG_ECDSA_SECP192R1,      /*!< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
    ALG_ECDSA_SECP224R1,      /*!< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
    ALG_ECDSA_SECP256R1,      /*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
    ALG_ECDSA_SECP384R1,      /*!< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
    ALG_ECDSA_SECP521R1,      /*!< Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1. */
    ALG_ECDSA_BP256R1,        /*!< Domain parameters for 256-bit Brainpool curve. */
    ALG_ECDSA_BP384R1,        /*!< Domain parameters for 384-bit Brainpool curve. */
    ALG_ECDSA_BP512R1,        /*!< Domain parameters for 512-bit Brainpool curve. */
    ALG_ECDSA_CURVE25519,     /*!< Domain parameters for Curve25519. */
    ALG_ECDSA_SECP192K1,      /*!< Domain parameters for 192-bit "Koblitz" curve. */
    ALG_ECDSA_SECP224K1,      /*!< Domain parameters for 224-bit "Koblitz" curve. */
    ALG_ECDSA_SECP256K1,      /*!< Domain parameters for 256-bit "Koblitz" curve. */
    ALG_ECDSA_CURVE448,       /*!< Domain parameters for Curve448. */	
} EncryptionAlgorithmEnum;

typedef enum {
    C_2E_2S,
    C_2E_0S,
    C_1E_2S,
    C_1E_1S,
    C_0E_2S,
} KeyAggrementSchemeEnum;

/* pre-share key generation */
typedef enum {
	KEYEX_NOT_SUP,
	KEYEX_SYMMETRIC_KEY,
	KEYEX_ECDH_SECP224R1,
	KEYEX_ECDH_SECP256R1,
	KEYEX_ECDH_SECP384R1,
	KEYEX_ECDH_SECP521R1,
	KEYEX_ECDH_BP256R1,
	KEYEX_ECDH_BP384R1,
	KEYEX_ECDH_BP512R1,
	KEYEX_ECDH_CURVE25519,
	KEYEX_ECDH_SECP192K1,
	KEYEX_PSKG_ECDH_SECP224K1,
	KEYEX_ECDH_SECP256K1,
	KEYEX_ECDH_CURVE448,
}KeyExchangeEnum;

/* session key generation */
typedef enum {
	KEYDRV_NOT_SUP,
	KEYDRV_HMAC_SHA_1,
	KEYDRV_HMAC_SHA_256,
	KEYDRV_HMAC_SHA_384,
	KEYDRV_HMAC_SHA_512,			
	KEYDRV_HKDF_SHA1,
	KEYDRV_HKDF_SHA256,
	KEYDRV_HKDF_SHA384,
	KEYDRV_HKDF_SHA512,
	KEYDRV_AES_CMAC_128,
	KEYDRV_AES_CMAC_192,
	KEYDRV_AES_CMAC_256,
} KeyDeriveEnum;

typedef enum {

} DigestEnum;


#endif /* MBED_OS_PLATFORM_SECURE_FLASH_TRANSPORT_LAYER_SF_LIB_INCLUDE_SECUREFLASH_ENCRYPTION_ALG_H_ */
