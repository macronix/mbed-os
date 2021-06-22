#include <stdlib.h>
#include "sf_library.h"
#include "rtos/ThisThread.h"
#include "platform/mbed_assert.h"
#include "FlashIAP.h"
#include "qcbor.h"
#include <time.h>

#ifndef MBED_CONF_MBED_TRACE_ENABLE
#define MBED_CONF_MBED_TRACE_ENABLE        1
#endif

#ifndef MBED_TRACE_MAX_LEVEL
#define MBED_TRACE_MAX_LEVEL TRACE_LEVEL_DEBUG
#endif

#include "mbed_trace.h"
#define TRACE_GROUP "ARMORFLASH"

#define DEFAULT_PUFRD_CBC_KEY_ID 0

#define MFR_ID_MACRONIX 0xC2

#define IS_MEM_READY_MAX_RETRIES 10000
#define ERASE_4K  0x1000
#define ERASE_32K 0x8000
#define ERASE_64K 0x10000
-
#define PROGRAM_256B 0x200

#define ARMOR_PUFRD_CBC_KEY_ID 0

/* for default Init */
#define  ROOT_KEY_0_ID 0x00
#define  USER_KEY_1_ID 0x01
#define  USER_KEY_2_ID 0x02
#define  USER_KEY_3_ID 0x03

#define LKD_REG_LOCK     0x00
#define LKD_REG_NOT_LOCK 0xFF

mbed::FlashIAP flash;
static data_isolation_t data_isolation;
secure_flash_meta_t meta;

static int flashiap_erase(size_t addr, size_t size);
static int flashiap_program(size_t addr, uint8_t *data, size_t size);
static int flashiap_read(size_t addr, uint8_t *data, size_t size);

SecureFlashLib::SecureFlashLib(SECURE_FLASH_TYPE *flash, int freq)
    : _sf_transport(flash, freq)
{
}

/****************************/
/* secure flash APIs        */
/****************************/
int SecureFlashLib::init()
{
	int status = MXST_SUCCESS;
	uint8_t id[3];		

	MX_DBG("ArmorFlash initial start\r\n");

	if (_sf_transport.init()) {
		return MXST_TRANS_INIT_ERR;
	}

	status = _std_sw_reset();
	if (MXST_SUCCESS != status) {
		return status;
	}

	status = _std_read_id(id, 3);
	if (MXST_SUCCESS != status) {
		return status;
	}

	MX_DBG("ID: %02X%02X%02X\r\n", id[0], id[1], id[2]);
	manufacture_id = id[0];

	_density = 1llu << (id[2] & 0x3F);
	_security_field_density = SECURE_MEM_SIZE;
	MX_DBG("Standard memory size: %llu-bytes\r\n"
		   "Secure memory size:: %llu-bytes\r\n",
		   _density - _security_field_density, _density);

	if ((1 << 24) < _density) {
		status = _std_en4b();
		if (MXST_SUCCESS != status)
			return status;
	}	
	/* Enter security field */
	memset(&meta, 0, sizeof(meta));
	meta.op_mac_params.is_inc_ext_zone = TRUE;
	meta.op_mac_params.is_inc_linked_mc = TRUE;
	meta.op_mac_params.is_inc_sn = TRUE;
	meta.is_omac_en = FALSE;

	status = switch_security_field(TRUE);
	if (MXST_SUCCESS != status) {
		return status;
	}

#ifdef DATAZONE_ISOLATION_MODULE
	 status = flash.init();
	 if (0 != status) {
		return MXST_ERR;
	 }	
#endif

	return _get_security_field_info();
}

int SecureFlashLib::deinit()
{
	int status = MXST_SUCCESS;

	status = switch_security_field(FALSE);
	if (MXST_SUCCESS != status) {
		return status;
	}
	if (_sf_transport.deinit()) {
		return MXST_TRANS_DEINIT_ERR;
	}
	return status;
}

int SecureFlashLib::lock_provision_data(void *provision_data_input)
{
	return MXST_SUCCESS;
}

int SecureFlashLib::_decode_provision_data_by_cbor()
{
	QCBORError         uErr;
    QCBORDecodeContext DecodeCtx;	

    /* Let QCBORDecode internal error tracking do its work. */
    QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&DecodeCtx, NULL);
    QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
    QCBORDecode_GetDoubleInMapSZ(&DecodeCtx, "DesignedCompression", &(pE->dDesignedCompresion));
    QCBORDecode_GetBoolInMapSZ(&DecodeCtx, "Turbo", &(pE->bTurboCharged));

    QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "NumCylinders", &(pE->uNumCylinders));

    /* Check the internal tracked error now before going on to
     * reference any of the decoded data, particularly
     * pE->uNumCylinders */
    uErr = QCBORDecode_GetError(&DecodeCtx);
    if(uErr != QCBOR_SUCCESS) {
        goto Done;
    }

    if(pE->uNumCylinders > MAX_CYLINDERS) {
        return TooManyCylinders;
    }

    QCBORDecode_EnterArrayFromMapSZ(&DecodeCtx, "Cylinders");
    for(int64_t i = 0; i < pE->uNumCylinders; i++) {
        QCBORDecode_GetDouble(&DecodeCtx,
                              &(pE->cylinders[i].dMeasuredCompression));
    }
    QCBORDecode_ExitArray(&DecodeCtx);
    QCBORDecode_ExitMap(&DecodeCtx);

    /* Catch further decoding error here */
    uErr = QCBORDecode_Finish(&DecodeCtx);

Done:
    return ConvertError(uErr);
}

int SecureFlashLib::write_provision_data(void *provision_data_input)
{
	int status = SECUREFLASH_BD_ERROR_OK;

	if (!provision_data_input) {
		return MXST_BUF_NULL;
	}

	flashiap_erase(PROVISION_DATA_ADDRESS, sizeof(priv_provision_data_t));
	flashiap_program(PROVISION_DATA_ADDRESS, (uint8_t *)provision_data_input, sizeof(priv_provision_data_t));	
	
	return MXST_SUCCESS;
}

int SecureFlashLib::read_provision_data(void *provision_data_output)
{
	flashiap_read(PROVISION_DATA_ADDRESS, (uint8_t *)provision_data_output, sizeof(priv_provision_data_t));	

	return MXST_SUCCESS;
}

int SecureFlashLib::parse_provision_data(void *provision_data_input, encryption_indicator_t *indicator)
{
	priv_provision_data_t provision_data = {};

	if (!indicator) {
		return MXST_BUF_NULL;
	}

	if (NULL == provision_data_input) {		
		flashiap_read(PROVISION_DATA_ADDRESS, (uint8_t *)&provision_data, sizeof(priv_provision_data_t));
	} else {
		memcpy(&provision_data, (uint8_t *)provision_data_input, sizeof(priv_provision_data_t));
		memcpy(&meta.region, &provision_data.message.region, sizeof(secure_flash_region_t));
	}

	memcpy(&secure_flash_profile, &provision_data.message.secure_flash_profile, sizeof(secure_flash_profile_t));
	memcpy(&data_isolation, &provision_data.message.data_isolation, sizeof (data_isolation_t));	

	indicator->operation = ENCOP_SIGNATURE_VERIFY;
	indicator->encryption = provision_data.signature.encryption;
	indicator->ecdsa.message = (uint8_t *)&provision_data.message;
	indicator->ecdsa.message_len = sizeof(provision_data.message);
	indicator->ecdsa.signature = (uint8_t *)&provision_data.signature.value; 
	indicator->ecdsa.signature_len = provision_data.signature.len; 
	indicator->ecdsa.pub_key = provision_data.message.rot_pub_key.value;
	indicator->ecdsa.pub_key_len = provision_data.message.rot_pub_key.len;

	return MXST_SUCCESS;
}
typedef struct {
	uint8_t challenge[ARMOR_TRNG_SIZE];
	uint64_t app_id;
	uint8_t *pub_key;
} challenge_t;
static challenge_t challenge_data;

int SecureFlashLib::get_challenge(uint64_t app_id, uint8_t *challenge)
{
	int status = MXST_SUCCESS, n;
	static uint8_t challenge[ARMOR_TRNG_SIZE] = {};

	for (n = 0; n < data_isolation.num; n++) {
		if (app_id == data_isolation.app_meta[n].app_id) {
			status = get_trng(challenge, ARMOR_TRNG_SIZE);
			if (MXST_SUCCESS != status) {
				return status;
			}
			break;
		}
	}
	if (data_isolation.num == n) {
		return MXST_ERR;
	}

	memcpy(challenge_data.challenge, challenge, ARMOR_TRNG_SIZE);
	challenge_data.app_id = app_id;	

	return status;
}

int SecureFlashLib::get_ecdsa_256r1_params(uint8_t *response, uint8_t *message, uint64_t *messgae_len, uint8_t *pub_key, uint8_t *sig)
{
	int n;

	for (n = 0; n < data_isolation.num; n++) {
		if (challenge_data.app_id == data_isolation.app_meta[n].app_id) {
			pub_key = data_isolation.app_meta[n].pub_key;			
			break;
		}
	}

	if (data_isolation.num == n) {
		return MXST_ERR;
	}

	message = challenge_data.challenge;
	*message_len = ARMOR_TRNG_SIZE;
	sig = response;	

	return MXST_SUCCESS;
}

int SecureFlashLib::default_provisioning()
{
    int status = MXST_SUCCESS;

//     // const uint8_t mc_default_val[ARMOR_MC_TOTAL_SIZE] = {
//     // 		0x00, 0x00, 0x02, 0x00,/* MC0 */
// 	// 		0x00, 0x00, 0x03, 0x00,/* MC1 */
// 	// 		0x00, 0x00, 0x04, 0x00,/* MC2 */
// 	// 		0x00, 0x00, 0x05, 0x00,/* MC3 */
//     // };

// 	uint8_t key_cfg[ARMOR_KEY_CFG_TOTAL_SIZE] = {
// 		0x48, 0x00, 0x20, 0xEF,     /* MACID:0, LinkedKey:0 */
// 		0x48, 0x00, 0x20, 0xEF,     /* MACID:0, LinkedKey:0 */
// 		0x58, 0x11, 0x20, 0xEF,     /* MACID:0, LinkedKey:0 */
// 		0x58, 0x11, 0x20, 0xEF      /* MACID:0, LinkedKey:2 */
// 	};

// 	uint8_t datazone_cfg[ARMOR_DATAZONE_CFG_TOTAL_SIZE] = {
// 		0x1F, 0xC1, 0x66, 0xFF,     /* D0 R:0, W:0, M:0 */
// 		0x1F, 0xC1, 0x66, 0xFF,     /* D1 R:1, W:1, M:1 */
// 		0x1F, 0xC1, 0x66, 0xFF,     /* D2 R:2, W:2, M:2 */
// 		0x1F, 0xC1, 0x66, 0xFF,     /* D3 R:3, W:3, M:3 */
// 		0x2F, 0xC2, 0xA6, 0xFF,     /* D4 R:0, W:1, M:2 */
// 		0x2F, 0xC2, 0xA6, 0xFF,     /* D5 R:1, W:2, M:3 */
// 		0x2F, 0xC2, 0xA6, 0xFF,     /* D6 R:2, W:3, M:0 */
// 		0x2F, 0xC2, 0xA6, 0xFF,     /* D7 R:3, W:0, M:1 */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* D8 R:0, W:1, M:2, SN */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* D9 R:0, W:1, M:2, Extra */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* DA R:0, W:1, M:2, SN, Extra */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* DB default */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* DC default */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* DD default */
// 		0x3F, 0xC3, 0xE6, 0xFF,     /* DE default */
// 		0x3F, 0xC3, 0xE6, 0xFF      /* DF default */
// 	};

// 	uint8_t mc_cfg[ARMOR_MC_CFG_TOTAL_SIZE] = {
// 		0x03, 0x00,
// 		0x07, 0x11,
// 		0x0b, 0x22,
// 		0x0f, 0x33
// 	};

// //	uint8_t root_key_0[ARMOR_KEY_SIZE] = {
// //		0xC9, 0xA0, 0x19, 0x17, 0x58, 0x0F, 0xB7, 0x6F,
// //		0xAD, 0x20, 0x50, 0xDC, 0x98, 0x86, 0xEA, 0xEC,
// //		0x05, 0x66, 0x3F, 0x5F, 0x4C, 0x35, 0x89, 0x0B,
// //		0x50, 0xCC, 0x2F, 0xDE, 0x01, 0xF6, 0xCD, 0xF1
// //	};
// //
// //	uint8_t user_key_1[ARMOR_KEY_SIZE] = {
// //		0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71,
// //		0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71,
// //		0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71,
// //		0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71
// //	};
// //
// //	uint8_t user_key_2[ARMOR_KEY_SIZE] = {
// //		0x68, 0x11, 0x3a, 0x03, 0x04, 0x85, 0xe6, 0x0e,
// //		0x52, 0x7f, 0x0A, 0x0B, 0xdd, 0xfD, 0x4E, 0xee,
// //		0x0f, 0x8b, 0x0D, 0x0C, 0xcd, 0x39, 0x09, 0x2e,
// //		0xb7, 0xd7, 0x05, 0x04, 0x03, 0x27, 0xf1, 0x7d
// //	};
// //
// //	uint8_t user_key_3[ARMOR_KEY_SIZE] = {
// //		0xA5, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
// //		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
// //		0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38,
// //		0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30
// //	};

// 	uint8_t lkd_reg[ARMOR_LKD_REG_TOTAL_SIZE] = {
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_CONFIG */
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_KEY */
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_EXTRAZONE */
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_MC */
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_PUF */
// 		LKD_REG_NOT_LOCK, /* TARGET_LKD_CERS */
// 	};

// 	status = get_all_sfconfig(NULL, SECURE_FLASH_VERBOSE);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* set key value before locking */
// 	// if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK)) {
// 	// 	memcpy(meta.region.key[ROOT_KEY_0_ID], root_key_0, ARMOR_KEY_SIZE); /* KEY0 */
// 	// 	memcpy(meta.region.key[USER_KEY_1_ID], user_key_1, ARMOR_KEY_SIZE); /* KEY1 */
// 	// 	memcpy(meta.region.key[USER_KEY_2_ID], user_key_2, ARMOR_KEY_SIZE); /* KEY2 */
// 	// 	memcpy(meta.region.key[USER_KEY_3_ID], user_key_3, ARMOR_KEY_SIZE); /* KEY3 */
// 	// }
// 	/* set spare zone value before locking */
// 	//TODO: Add if need
// 	/* set extra_zone value before locking */
// 	//TODO: Add if need

// 	MX_DBG("Start default provision\r\n");

// 	MX_DBG("ArmorFlash provision step 1 : Setup Data Zone, Key and MC configurations\r\n");
// 	/* set config value to ArmorFlash before locking */
// 	if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_CONFIG] & ARMOR_LKD_REG_MASK)) {

// 		/* set data zone config value to ArmorFlash before locking */
// 		status = _set_sfconfig(ARMOR_DATAZONE_CFG_MEM_ADDR, datazone_cfg, ARMOR_DATAZONE_CFG_TOTAL_SIZE);
// 		if (MXST_SUCCESS != status)
// 			return status;
// 		MX_DBG("Write data zone configuration done\r\n");

// 		/* set key configuration value to ArmorFlah before locking */
// 		status = _set_sfconfig(ARMOR_KEY_CFG_MEM_ADDR, key_cfg, ARMOR_KEY_CFG_TOTAL_SIZE);
// 		if (MXST_SUCCESS != status)
// 			return status;
// 		MX_DBG("Write key configuration done\r\n");

// 		/* set monotonic counter configuration value to ArmorFlash before locking */
// 		status = _set_sfconfig(ARMOR_MC_CFG_MEM_ADDR, mc_cfg, ARMOR_MC_CFG_TOTAL_SIZE);
// 		if (MXST_SUCCESS != status)
// 			return status;
// 		MX_DBG("Write MC configuration done\r\n");

// 	} else {
// 		MX_DBG("[SKIPPED], ConfigLKD register is locked\r\n");
// 	}

// 	status = get_all_sfconfig(NULL, SECURE_FLASH_VERBOSE);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	MX_DBG("ArmorFlash provision step 2 : Write the value of MC1 to 4 as 0 \r\n");
// 	/* set monotonic counter value before locking */
// 	// if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_MC] & ARMOR_LKD_REG_MASK)) {
// 	//     for (n = 0; n < ARMOR_MC_NUM * ARMOR_MC_SIZE; n+= ARMOR_MC_SIZE) {
// 	//         status = set_mc(n / ARMOR_MC_SIZE, &mc_default_val[n]);
// 	//         if (MXST_SUCCESS != status)
// 	//     	    return status;
// 	//     }
// 	// } else {
// 	// 	MX_DBG("[SKIPPED], MCLKD register is locked\r\n");
// 	// }

// //	MX_DBG("ArmorFlash provision step 3 : [SPI Write] write key\r\n");
// //	/* set key value to ArmorFlash before locking */
// //	if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK)) {
// //		 /* write root key through standard SPI */
// //		status = update_key(meta.region.key[ROOT_KEY_0_ID], ROOT_KEY_0_ID, SF_SET_KEY_SPI_WR);
// //		if (MXST_SUCCESS != status)
// //			return status;
// //		MX_DBG("Write root key to key 0 done\r\n");
// //
// //		/* write user key 1 through standard SPI program */
// //		status = update_key(meta.region.key[USER_KEY_1_ID], USER_KEY_1_ID, SF_SET_KEY_SPI_WR);
// //		if (MXST_SUCCESS != status)
// //			return status;
// //		MX_DBG("Write user key 1 to key 1 done\r\n");
// //
// //		/* write user key 2 through standard SPI program */
// //		status = update_key(meta.region.key[USER_KEY_2_ID], USER_KEY_2_ID, SF_SET_KEY_SPI_WR);
// //		if (MXST_SUCCESS != status)
// //			return status;
// //		MX_DBG("Write user key 2 to key 2 done\r\n");
// //
// //		/* write user key 3 through standard SPI program */
// //		status = update_key(meta.region.key[USER_KEY_3_ID], USER_KEY_3_ID, SF_SET_KEY_SPI_WR);
// //		if (MXST_SUCCESS != status)
// //			return status;
// //		MX_DBG("Write user key 3 to key 3 done\r\n");
// //	} else {
// //		MX_DBG("[SKIPPED], KeyLKD register is locked\r\n");
// //	}

// 	MX_DBG("ArmorFlash provision step 3 : lock down\r\n");
// 	if (LKD_REG_LOCK == lkd_reg[TARGET_LKD_CONFIG]) {
// 		if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_CONFIG] & ARMOR_LKD_REG_MASK)) {
// 			// status = _lock_down(TARGET_LKD_CONFIG, 0);
// 			// if (MXST_SUCCESS != status)
// 			// 	return status;
// 			MX_DBG("ConfigLKD register lock-down successfully.\r\n");
// 		} else {
// 			MX_DBG("[SKIPPED] ConfigLKD register has been locked\r\n");
// 		}
// 	} else {
// 		MX_DBG("[SKIPPED] ConfigLKD register, %02X\r\n", meta.region.sf_config.lock_reg[TARGET_LKD_CONFIG]);
// 	}

// 	if (LKD_REG_LOCK == lkd_reg[TARGET_LKD_KEY]) {
// 		if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK)) {
// 			// status = _lock_down(TARGET_LKD_KEY, 0);
// 			// if (MXST_SUCCESS != status)
// 			// 	return status;
// 			MX_DBG("KeyLKD register lock-down successfully.\r\n");
// 		} else {
// 			MX_DBG("[SKIPPED] KeyLKD register has been locked\r\n");
// 		}
// 	} else {
// 		MX_DBG("[SKIPPED] KeyLKD register, %02X\r\n", meta.region.sf_config.lock_reg[TARGET_LKD_KEY]);
// 	}

// 	if (LKD_REG_LOCK == lkd_reg[TARGET_LKD_EXTRAZONE]) {
// 		if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_EXTRAZONE] & ARMOR_LKD_REG_MASK)) {
// 			// status = _lock_down(TARGET_LKD_EXTRAZONE, 0);
// 			// if (MXST_SUCCESS != status)
// 			// 	return status;
// 			MX_DBG("ExtraZoneLKD register lock-down successfully.\r\n");
// 		} else {
// 			MX_DBG("[SKIPPED] ExtraZoneLKD register has been locked\r\n");
// 		}
// 	} else {
// 		MX_DBG("[SKIPPED] ExtraZoneLKD register, %02X\r\n", meta.region.sf_config.lock_reg[TARGET_LKD_EXTRAZONE]);
// 	}

// 	if (LKD_REG_LOCK == lkd_reg[TARGET_LKD_MC]) {
// 		if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_MC] & ARMOR_LKD_REG_MASK)) {
// 			// status = _lock_down(TARGET_LKD_MC, 0);
// 			// if (MXST_SUCCESS != status)
// 			// 	return status;
// 			MX_DBG("MCLKD register lock-down successfully.\r\n");
// 		} else {
// 			MX_DBG("[SKIPPED] MCLKD register has been locked\r\n");
// 		}
// 	} else {
// 		MX_DBG("[SKIPPED] MCLKD register, %02X\r\n", meta.region.sf_config.lock_reg[TARGET_LKD_MC]);
// 	}

// 	if (LKD_REG_LOCK == lkd_reg[TARGET_LKD_PUF]) {
// 		if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_PUF] & ARMOR_LKD_REG_MASK)) {
// 			// status = _lock_down(TARGET_LKD_PUF, 0);
// 			// if (MXST_SUCCESS != status)
// 			// 	return status;
// 			MX_DBG("PUFLKD register lock-down successfully.\r\n");
// 		} else {
// 			MX_DBG("[SKIPPED] PUFLKD register has been locked\r\n");
// 		}
// 	} else {
// 		MX_DBG("[SKIPPED] PUFLKD register, %02X\r\n", meta.region.sf_config.lock_reg[TARGET_LKD_PUF]);
// 	}

// 	status = _get_security_field_info();
// 	if (MXST_SUCCESS != status) {
// 		return status;
// 	}

// 	MX_DBG("default provision is successful\r\n");

	return status;
}

void SecureFlashLib::get_secure_flash_profile(secure_flash_profile_t *sf_profile)
{
	memcpy(sf_profile, &secure_flash_profile, sizeof(secure_flash_profile));
}

int SecureFlashLib::set_cipher_suite(cipher_suite_t *cipher_suite)
{
	/* write cipher suite to secure flash if needed */
	return MXST_SUCCESS;
}

// int SecureFlashLib::_check_nonce(uint8_t cbc_key_id)
// {
// 	int status = MXST_SUCCESS;

//     meta.is_nrandom_set = (meta.region.sf_config.key_config[cbc_key_id][KEY_CFG_BYTE_3] & KEY_CFG_NRANDOM_MASK) > 0;
// 	if (meta.is_nrandom_set || !meta.is_nonce_valid) {
// 		if (!meta.is_sf_trng_en) {
// 			MX_INFO("When the NRANDOM bit is set to 1, the ConfigLKD register must be locked.\r\n");
// 		}
// 		status = _get_nonce(NULL);
// 	}

// 	status = _get_macount();
// 	if (MXST_SUCCESS != status)
// 		return status;
// 	if (0xFF == _sf_params.encryption.iv.macount || !_sf_params.encryption.iv.macount) {
// 		return  _get_nonce(NULL);
// 	}
// 	return status;
// }

/*
 * Function:     switch_security_field
 * Arguments:	 enter_secure_field, enter or exit security mode. TRUE: enter security mode; FALSE: exit security mode.
 * Return Value: MXST_SUCCESS.
 *               MXST_FAILURE.
 * Description:  This function is for entering or exiting the security mode.
 */
int SecureFlashLib::switch_security_field(uint8_t enter_secure_field)
{
 	int status = MXST_SUCCESS;
	uint8_t scur_reg;

	if (meta.is_sf_mode == enter_secure_field) {
		MX_DBG("do nothing, already %s\r\n", enter_secure_field ? "entered secure field" : "exited secure field\r\n");
		return MXST_SUCCESS;
	}

 	if (enter_secure_field) {
 		status = _std_ensf();
		if (MXST_SUCCESS != status)
			return status;

		status = _std_read_scur(&scur_reg, 1);
		if (MXST_SUCCESS != status)
			return status;

		if (!(scur_reg & SCUR_BIT_ENSF)) {
			MX_ERR("rdscur: %02X, error\r\n", scur_reg);
			return MXST_ARMOR_ENSF_ERR;
		}
 		meta.is_sf_mode = TRUE;
 		MX_DBG("Enter security field!\r\n");
 	} else {
 		status = _std_exsf();
		if (MXST_SUCCESS != status)
			return status;

		status = _std_read_scur(&scur_reg, 1);
		if (MXST_SUCCESS != status)
			return status;

		if (scur_reg & SCUR_BIT_ENSF) {
			MX_ERR("rdscur: %02X, error\r\n", scur_reg);
			return MXST_ARMOR_EXSF_ERR;
		}
 		meta.is_sf_mode = FALSE;
 		MX_DBG("Exit to security field\r\n");
 	}
 	return status;
}

/*
 * Function:        read
 * Arguments:       addr, the address of data zone.
 *                  buf,  a pointer to read buffer.
 *                  size, number of bytes to read.
 * Description:     This function is for reading data from ArmorFlash.
 */
// int SecureFlashLib::read(uint32_t addr, uint8_t *buf, uint8_t size)
// {
//     int status = MXST_SUCCESS;
//     uint8_t target_datazone_id;

//     target_datazone_id = addr / ARMOR_DATAZONE_SIZE;

//     if (meta.region.sf_config.data_config[target_datazone_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_ENCRD_MASK) {

//     	/* get CBC key ID for check if nonce need random*/
//     	_get_key_id_by_cmd(ARMOR_INST_ENCRD, target_datazone_id, 0);

//         status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
//     	if (MXST_SUCCESS != status) {
//     		return status;
//     	}

// 		status = _check_macount();
// 		if (MXST_SUCCESS != status) {
// 			return status;
// 		}

//         status = _armor_encrd(addr, buf, size);
//     } else {
//         status = _armor_pgrd(addr, buf, size);
//     }

//     return status;
// }

/*
 * Function:      program
 * Arguments:	  addr, the address of data zone.
 *                buf,  a pointer to a program buffer where the program data will be stored.
 *                byte, number of bytes to program.
 * Description:   This function is for programming data to the ArmorFlash.
 */

// int SecureFlashLib::program(uint32_t addr, const uint8_t *buf, uint8_t size)
// {
//     int status = MXST_SUCCESS;
//     uint8_t target_datazone_id;

//     target_datazone_id = addr / ARMOR_DATAZONE_SIZE;

//     status = _check_cmd_permit(ARMOR_INST_ENCWR, target_datazone_id);
// 	if (MXST_SUCCESS != status)
// 		return status;

//     /* get CBC key ID for check if nonce need random*/
//     _get_key_id_by_cmd(ARMOR_INST_ENCWR, target_datazone_id, 0);

//     status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	status = _check_macount();
// 	if (MXST_SUCCESS != status)
// 		return status;

//     _armor_encwr(addr, buf, size, OP_ENCWR_PGM);

//     return status;
// }

/*
 * Function:      erase
 * Arguments:	  addr, the address of data zone(should be aligned with 4k-bytes).
 * Description:   The erasure is started by aligning the 4K bytes of address.
 */
// int SecureFlashLib::erase(uint32_t addr)
// {
//     int status = MXST_SUCCESS;
//     uint8_t target_datazone_id;
//     uint8_t buf[ARMOR_DATA_MAX_SIZE] = {};

//     target_datazone_id = addr / ARMOR_DATAZONE_SIZE;

//     status = _check_cmd_permit(ARMOR_INST_ENCWR, target_datazone_id);
//     if (MXST_SUCCESS != status)
//     	return status;

//     /* get CBC key ID for check if nonce need random*/
//     _get_key_id_by_cmd(ARMOR_INST_ENCWR, target_datazone_id, 0);

//     status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
//     if (MXST_SUCCESS != status) {
//         return status;
//     }

// 	status = _check_macount();
// 	if (MXST_SUCCESS != status) {
// 	    return status;
// 	}

// 	memset(buf, 0xFF, ARMOR_DATA_MAX_SIZE);
//      _armor_encwr(addr, buf, ARMOR_DATA_MAX_SIZE, OP_ENCWR_ERS_4K);

//      return status;
// }

int SecureFlashLib::_prepare_secure_write_packet(command_params_t *cmd_params, encryption_indicator_t *enc_indicator)
{
	int status = MXST_SUCCESS;

	status = _prepare_secure_write_packet_base(cmd_params);
	if (MXST_SUCCESS != status) {
		return status;
	}

	switch (cmd_params->name) {	
	case CMDNAME_PROGRAM:
	case CMDNAME_ERASE:
		memcpy(cmd_params->write_packet.mac_data_crc, enc_indicator->aes_ccm_gcm.tag, ARMOR_MAC_SIZE);
		memcpy(cmd_params->write_packet.mac_data_crc + ARMOR_MAC_SIZE, enc_indicator->aes_ccm_gcm.odata, ARMOR_DATA_MAX_SIZE);	
	case CMDNAME_INCR_MC:
		break;
	default:
		break;		
	}

	/* compute crc16 for secure packet */
	 _compute_crc(cmd_params->write_packet.count - ARMOR_PKT_CRC_SIZE,
	 		(uint8_t *)&cmd_params->write_packet,
	 		((uint8_t *)&cmd_params->write_packet) + (cmd_params->write_packet.count - ARMOR_PKT_CRC_SIZE));
	return status;
}

int SecureFlashLib::_prepare_secure_write_packet_base(command_params_t *cmd_params)
{
	int status = MXST_SUCCESS;
    uint8_t inst;

	switch (cmd_params->cmd_name) {
	case CMDNAME_READ:
		inst = ARMOR_INST_ENCRD;
		meta.is_imac_en = FALSE;
		meta.is_omac_en = TRUE;

		cmd_params->write_pkt.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;
		cmd_params->write_pkt.inst = inst;
		cmd_params->write_pkt.op = _set_op_by_mac_params(inst, 0);
		cmd_params->write_pkt.var1[0] = (cmd_params->address >> 16);
		cmd_params->write_pkt.var1[1] = (cmd_params->address >> 8);
		cmd_params->write_pkt.var1[2] = (cmd_params->address >> 0);
		cmd_params->write_pkt.var2[0] = 0;
		cmd_params->write_pkt.var2[1] = (uint8_t)cmd_params->odata_len;	
		break;
	case CMDNAME_PROGRAM:
		intst = ARMOR_INST_ENCWR;
		meta.is_imac_en = TRUE;
		meta.is_omac_en = FALSE;	

		cmd_params->write_pkt.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + ARMOR_MAC_SIZE + ARMOR_DATA_MAX_SIZE;
		cmd_params->write_pkt.inst = intst;
		cmd_params->write_pkt.op = _set_op_by_mac_params(intst, OP_ENCWR_PGM);
		cmd_params->write_pkt.var1[0] = (cmd_params->address >> 16);
		cmd_params->write_pkt.var1[1] = (cmd_params->address >> 8);
		cmd_params->write_pkt.var1[2] = (cmd_params->address >> 0);
		cmd_params->write_pkt.var2[0] = 0;
		cmd_params->write_pkt.var2[1] = ARMOR_DATA_MAX_SIZE;
		break;
	case CMDNAME_ERASE:
		inst = ARMOR_INST_ENCWR;
		meta.is_imac_en = TRUE;
		meta.is_omac_en = FALSE;	

		cmd_params->write_pkt.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + ARMOR_MAC_SIZE + ARMOR_DATA_MAX_SIZE;
		cmd_params->write_pkt.inst = intst;
		cmd_params->write_pkt.op = _set_op_by_mac_params(intst, OP_ENCWR_ERS_4K);
		cmd_params->write_pkt.var1[0] = (cmd_params->address >> 16);
		cmd_params->write_pkt.var1[1] = (cmd_params->address >> 8);
		cmd_params->write_pkt.var1[2] = (cmd_params->address >> 0);
		cmd_params->write_pkt.var2[0] = 0;
		cmd_params->write_pkt.var2[1] = ARMOR_DATA_MAX_SIZE;
		break;
	case CMDNAME_RD_PUF:
		intst = ARMOR_INST_PUFRD;
		meta.is_imac_en = FALSE;
		meta.is_omac_en = TRUE;

		cmd_params->write_pkt.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;
		cmd_params->write_pkt.inst = intst;
		cmd_params->write_pkt.op = _set_op_by_mac_params(intst, 0);
		cmd_params->write_pkt.var1[0] = 0;
		cmd_params->write_pkt.var1[1] = DEFAULT_PUFRD_CBC_KEY_ID;
		cmd_params->write_pkt.var1[2] = 0;
		cmd_params->write_pkt.var2[0] = 0;
		cmd_params->write_pkt.var2[1] = 0;
		break;
	case CMDNAME_RD_TRNG:
		inst = ARMOR_INST_RGEN;
		meta.is_imac_en = FALSE;
		meta.is_omac_en = FALSE;

		if (meta.is_sftrng_en) {
			MX_DBG("ArmorFlash ConfigLKD register is locked, the RGEN command is enabled\r\n");
		} else {
			MX_INFO("ArmorFlash ConfigLKD register is un-locked, the RGEN command will generate a fixed pattern\r\n");
		}

		cmd_params->write_pkt.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;
		cmd_params->write_pkt.inst = inst;
		cmd_params->write_pkt.op = _set_op_by_mac_params(inst, 0);
		cmd_params->write_pkt.var1[0] = 0;
		cmd_params->write_pkt.var1[1] = 0;
		cmd_params->write_pkt.var1[2] = 0;
		cmd_params->write_pkt.var2[0] = 0;
		cmd_params->write_pkt.var2[1] = 0;
		break;

	default:
		return MXST_NOT_DEFINED;
	}
	return status;
}

int SecureFlashLib::write_secure_packet(command_params_t *cmd_params, encryption_indicator_t *enc_indicator)
{
	int status = MXST_SUCCESS;
	uint8_t inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_WRITE_4B : STD_INST_SECURE_WRITE;	

	/* wait for WIP ready */
	status = _is_mem_ready();
	if (MXST_SUCCESS != status)
		return status;

	status = _check_wren();
	if (MXST_SUCCESS != status)
		return status;

	/* packet buffer address reset */	
	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_RESET_ADDR, NULL, 0)) {
		MX_ERR("Write secure packet failed\r\n");
		return MXST_ARMOR_WR_SECURE_PKT_ERR;
	}

	/* wait for WIP ready */
	status = _is_mem_ready();
	if (MXST_SUCCESS != status)
		return status;	 

	status = _check_wren();
	if (MXST_SUCCESS != status)
		return status;

	status = _prepare_secure_write_packet(cmd_params, enc_indicator);
	if (MXST_SUCCESS != status) {
		return status;
	}

	/* write secure packet through the address : ARMOR_PKT_ADDR*/	
	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_ADDR, 
			(uint8_t *)&(cmd_params->write_packet), cmd_params->write_packet.count)) {
		MX_ERR("Write secure packet failed\r\n");
		return MXST_ARMOR_WR_SECURE_PKT_ERR;
	}
	return status;
}


int SecureFlashLib::read_secure_packet(command_params_t *cmd_params)
{
	int status = MXST_SUCCESS;
	uint8_t inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_READ_4B : STD_INST_SECURE_READ;

	status =_is_mem_ready_armor();
	if (MXST_SUCCESS != status) {
    	return status;
    }

    status = _check_sr_crc();
    if (MXST_SUCCESS != status) {
    	return status;
    }

	/* read secure packet through the address : ARMOR_PKT_ADDR*/	
    if (_sf_transport.read_secure_packet(inst, ARMOR_PKT_ADDR, 0, 
			(uint8_t *)&cmd_params->read_packet, sizeof(cmd_params->read_packet))) {
    	MX_ERR("Read secure packet failed\r\n");
    	return MXST_ARMOR_RD_SECURE_PKT_ERR;
    }

    status = _check_sr_crc();
    if (MXST_SUCCESS != status) {
    	return status;
    }

    status = _parse_security_error_code(cmd_params);
    if (MXST_SUCCESS != status) {
        MX_ERR("[ArmorFlash Error Code: %02X], %s\r\n", cmd_params->read_packet.return_code, meta.rtn_err_msg);
    } else {
		uint32_t data_size = cmd_params->read_packet.count - (ARMOR_PKT_COUNT_SIZE + ARMOR_PKT_RTN_CODE_SIZE + ARMOR_PKT_CRC_SIZE);

    	switch (cmd_params->name) {    	
		case CMDNAME_RD_TRNG:		
			memcpy(cmd_params->odata, cmd_params->read_packet.mac_data_crc, 
				(data_size > cmd_params->odata_len) ? cmd_params->odata_len : data_size);
			break;
		case CMDNAME_RD_UID:
			memcpy(cmd_params->odata, meta.region.sf_config.sn, 
				(data_size > cmd_params->odata_len) ? cmd_params->odata_len : data_size);
			break;
    	default:
    		break;
    	}
    }
    return status;
}

/*
 * Function:    write_read_secure_packet
 * Arguments:
 * Description: Write and read secure packets to and from ARMORFLASH
 */
// int SecureFlashLib::write_read_secure_packet(command_params_t *cmd_params)
// {
// 	int status = MXST_SUCCESS;
// 	uint8_t status_reg, inst;
// 	int retries = 0;

// 	/* wait for WIP ready */
// 	status = _is_mem_ready();
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	status = _check_wren();
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* packet buffer address reset */
// 	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_WRITE_4B : STD_INST_SECURE_WRITE;
// 	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_RESET_ADDR, NULL, 0)) {
// 		MX_ERR("Write secure packet failed\r\n");
// 		return MXST_ARMOR_WR_SECURE_PKT_ERR;
// 	}

// 	/* wait for WIP ready */
// 	status = _is_mem_ready();
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* Pack the MAC and data into a secure packet that will be sent to ArmorFlash. */
// 	memcpy(_sf_transport.secure_packet.write.mac_data_crc,
// 			sop->session.aes_ccm_gcm.tag, sop->session.aes_ccm_gcm.tag_len);
// 	memcpy(_sf_transport.secure_packet.write.mac_data_crc + security_operation_params->session.aes_ccm_gcm.tag_len,
// 			sop->session.aes_ccm_gcm.data, sop->session.aes_ccm_gcm.data_len);

// 	/* compute crc16 for secure packet */
// 	_compute_crc(_sf_transport.secure_packet.write.count - ARMOR_PKT_CRC_SIZE,
// 			(uint8_t *)&_sf_transport.secure_packet.write,
// 			((uint8_t *)&_sf_transport.secure_packet.write) + (_sf_transport.secure_packet.write.count - ARMOR_PKT_CRC_SIZE));

// 	status = _check_wren();
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* write secure packet through the address : ARMOR_PKT_ADDR*/
// 	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_WRITE_4B : STD_INST_SECURE_WRITE;
// 	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_ADDR, (uint8_t *)&(_sf_transport.secure_packet.write), _sf_transport.secure_packet.write.count)) {
// 		MX_ERR("Write secure packet failed\r\n");
// 		return MXST_ARMOR_WR_SECURE_PKT_ERR;
// 	}

// 	/* Polling for security packet readiness from ArmorFlash. */
// 	do {
// 		retries++;
// 		status = _std_read_sr(&status_reg, 1);
// 		if (MXST_SUCCESS != status)
// 			return status;
// 	} while ((!(status_reg & SF_SR_BIT_OUT_RDY) || (status_reg & SF_SR_BIT_WIP)) && retries < IS_MEM_READY_MAX_RETRIES);

// 	if (!(status_reg & SF_SR_BIT_OUT_RDY) || status_reg & SF_SR_BIT_WIP) {
// 		MX_ERR("time out, Flash is busy\r\n");
// 		return MXST_FLASH_NOT_READY;
// 	}

//     status = _check_sr_crc();
//     if (MXST_SUCCESS != status) {
//     	return status;
//     }

// 	/* read secure packet through the address : ARMOR_PKT_ADDR*/
// 	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_READ_4B : STD_INST_SECURE_READ;
//     if (_sf_transport.read_secure_packet(inst, ARMOR_PKT_ADDR, 0, (uint8_t *)&_sf_params.rd_secure_pkt, sizeof(_sf_params.rd_secure_pkt))) {
//     	MX_ERR("Read secure packet failed\r\n");
//     	return MXST_ARMOR_RD_SECURE_PKT_ERR;
//     }

//     status = _check_sr_crc();
//     if (MXST_SUCCESS != status) {
//     	return status;
//     }

//     status = _parse_security_error_code();
//     if (MXST_SUCCESS != status) {
//         MX_ERR("[ArmorFlash Error Code: %02X], %s\r\n", _sf_params.rd_secure_pkt.return_code, meta.rtn_err_msg);
//     } else {
//     	switch (_sf_transport.secure_packet.write.inst) {
//     	case ARMOR_INST_KGEN:
// 			memcpy(_sf_params.encryption.mac, _sf_params.rd_secure_pkt.mac_data, sop->session.aes_ccm_gcm.tag_len);
// 			sop->session.aes_ccm_gcm.data_len = ARMOR_KEY_SIZE;
// 			_get_aes_ccm_params(_sf_params.rd_secure_pkt.mac_data + ARMOR_MAC_SIZE, ACGO_AUTHEN_MAC_DECRYPT_KEY);

//     		break;
//     	case ARMOR_INST_MC:
//     		if (ACGO_ENCRYPT_MAC == sop->session.aes_ccm_gcm.operation) {
//     			memcpy(sop->session.aes_ccm_gcm.data, _sf_params.rd_secure_pkt.mac_data, ARMOR_MC_SIZE);
//     		}
//     	default:
//     		break;
//     	}
//     }
//     return status;
// }

// int SecureFlashLib::update_preshare_key(uint8_t *key, uint8_t key_id)
// {
// 	/* ArmorFlash does not support */
// 	return MXST_SUCCESS;
// }

// int SecureFlashLib::update_session_key(uint8_t *key, uint8_t key_id)
// {
// 	int status = MXST_SUCCESS;

// 	if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK)) {
// 		status = _update_key(key, key_id, UPDKEY_SPI_WR);
// 		if (MXST_SUCCESS != status) {
// 			return status;
// 		}
// 	}
// 	return _update_key(key, key_id, UPDKEY_SYNC);
// }

/*
 * Function:     update_key
 * Arguments:	 input_key,     the input key value when updating key by related command.
 * 				 target_key_id, the ID of target key which will be updated.
 * 				 method,        key update command.
 * Description:  This function is for updating the key value.
 */
// int SecureFlashLib::_update_key(uint8_t *input_key, uint8_t target_key_id, UpdateKeyMethodEnum method)
// {
// 	switch (method) {
// 	case UPDKEY_SPI_WR:
// 		return _spi_write_key(input_key, target_key_id);
// 	case UPDKEY_KWR:
// 		return _update_key_by_kwr(input_key, target_key_id);
// 	case UPDKEY_KGEN:
// 		return _update_key_by_kgen(target_key_id);
// 	case UPDKEY_KPUF:
// 		return _update_key_by_puf( target_key_id);
// 	case UPDKEY_SYNC:
// 		memcpy(meta.region.key[target_key_id], input_key, ARMOR_KEY_SIZE);
// 		break;
// 	default:
// 		return MXST_ARMOR_SET_KEY_METHOD_ERR;
// 	}
// 	return MXST_SUCCESS;
// }

/*
 * Function:     lock_configlkd_reg
 * Arguments:
 * Description:  Lock configuration memory and disable write permission.
 */
// int SecureFlashLib::lock_configlkd_reg()
// {
// 	return _lock_down(TARGET_LKD_CONFIG, 0);
// }

/*
 * Function:     lock_keylkd_reg
 * Arguments:
 * Description:  Prohibit the permission to update key by standard SPI write.
 */
// int SecureFlashLib::lock_keylkd_reg()
// {
// 	return _lock_down(TARGET_LKD_KEY, 0);
// }

/*
 * Function:     lock_configlkd_reg
 * Arguments:
 * Description:  Prohibit the permission to update individual key by security operation.
 */
// int SecureFlashLib::lock_individual_key(uint8_t key_id)
// {
// 	return _lock_down(TARGET_LKD_IND_KEY, key_id);
// }

/*
 * Function:        _set_sfconfig
 * Arguments:       cfg_blob, A pointer to the buffer that stores the blob of secure field configuration.
 *                  cfg_mask, A pointer to the buffer that stores the mask value of secure field configuration.
 * Description:     Set the security field configuration.
 */
int SecureFlashLib::set_all_sfconfig(const uint8_t *cfg_blob, const uint8_t *cfg_mask)
{
	int status = MXST_SUCCESS;
	uint32_t size = SECUREFIELD_CFG_SIZE, addr = SECUREFIELD_CFG_ADDR_S, remain;
	uint8_t cfg[SECUREFIELD_CFG_SIZE], *cfg_p;
	cfg_p = cfg;

	MBED_ASSERT(cfg_blob);
	MBED_ASSERT(cfg_mask);

	for (int n = 0; n < SECUREFIELD_CFG_SIZE; n++) {
		cfg_p[n] = (cfg_mask[n] & meta.region.sf_config.buf[n]) | ((~cfg_mask[n]) & cfg_blob[n]);
	}

	remain = addr % ARMOR_DATA_MAX_SIZE;
	if (remain) {
		remain = (ARMOR_DATA_MAX_SIZE - remain) > size ? size : ARMOR_DATA_MAX_SIZE - remain;
		status = _std_program(addr, cfg_p, remain);
		if (MXST_SUCCESS != status)
			return status;
		addr += remain;
		cfg_p += remain;
		size -= remain;
	}

	while (size) {
		remain = size > ARMOR_DATA_MAX_SIZE ? ARMOR_DATA_MAX_SIZE : size;
		status = _std_program(addr, cfg_p, remain);
		if (MXST_SUCCESS != status)
			return status;

		addr += remain;
		cfg_p += remain;
		size -= remain;
	}

	status = get_all_sfconfig(NULL, SECURE_FLASH_VERBOSE);
	if (MXST_SUCCESS != status)
		return status;
	if (memcmp(meta.region.sf_config.buf, cfg, SECUREFIELD_CFG_SIZE)) {
		MX_ERR("The comparison result of secure field configuration failed\r\n");
		status = MXST_ARMOR_SF_CFG_CMP_FAILED;
	}
	return status;
}

/*
 * Function:       get_all_sfconfig
 * Arguments:      buf, A pointer to the buffer that receives the secure field configuration from ArmorFlash.
 *                 verbose, show the information of secure field configurations.
 * Description:    This function is for reading all of the configuration data.
 */
int SecureFlashLib::get_all_sfconfig(uint8_t *buf, uint8_t verbose)
{
	int status = MXST_SUCCESS;
	uint32_t remain = SECUREFIELD_CFG_SIZE, read_size = 0, m = 0, n = 0;

	while (remain) {
		read_size = remain > ARMOR_DATA_MAX_SIZE ? ARMOR_DATA_MAX_SIZE : remain;
		status = _armor_pgrd(SECUREFIELD_CFG_ADDR_S + n, meta.region.sf_config.buf + n, read_size);
		if (MXST_SUCCESS != status)
			return status;
		remain -= read_size;
		n += read_size;
	}

	if (buf) {
		memcpy(buf, meta.region.sf_config.buf, SECUREFIELD_CFG_SIZE);
	}

	meta.is_sf_trng_en = (meta.region.sf_config.lock_reg[ARMOR_CFG_LKD_OFS]  & ARMOR_LKD_REG_MASK) != ARMOR_LKD_REG_NOT_LKD;

	if (verbose) {
		MX_INFO("------------------------------------\r\n");
		const char * LOCK_REG_INFO[] = {
		    "ConfigLKD    Register",
		    "KeyLKD       Register",
		    "ExtraZoneLKD Register",
		    "MCLKD        Register",
		    "PUFLKD       Register",
		    "ChipEraseLKD Register",
		};

		MX_INFO("Serial Number: ");
		for (n = 0; n < ARMOR_SN_SIZE; n++)
			MX_INFO("%02X", meta.region.sf_config.sn[ARMOR_SN_SIZE - n - 1]);
		MX_INFO("\r\n");

		for (n = 0; n < ARMOR_LKD_REG_TOTAL_SIZE; n++)
			MX_INFO("%s: %02X\r\n", LOCK_REG_INFO[n], meta.region.sf_config.lock_reg[n]);

		MX_INFO("Data Zone Configurations: \r\n");
		for (n = 0; n < ARMOR_DATAZONE_CFG_NUM; n++) {
			MX_INFO("DATA Config %02lu: ", n);
			for (m = 0; m < ARMOR_DATAZONE_CFG_SIZE; m++) {
				MX_DBG("%02X", meta.region.sf_config.data_config[n][m]);
			}
			MX_INFO(" >> RDID: %d, WRID: %d, MACID: %d \r\n",
					(meta.region.sf_config.data_config[n][0] & 0x30) >> 4,
					(meta.region.sf_config.data_config[n][1] & 0x03) >> 0,
					(meta.region.sf_config.data_config[n][2] & 0xC0) >> 6);
		}

		MX_INFO("KEY Configurations: \r\n");
		for (n = 0; n < ARMOR_KEY_CFG_NUM; n++) {
			MX_INFO("KEY  Config %02lu: ", n);
			for (m = 0; m < ARMOR_KEY_CFG_SIZE; m++) {
				MX_INFO("%02X", meta.region.sf_config.key_config[n][m]);
			}
			MX_INFO(" >> MACID: %d, LinkedKey: %d",
					(meta.region.sf_config.key_config[n][0] & 0x30) >> 4,
					(meta.region.sf_config.key_config[n][1] & 0x03) >> 0);
			if (meta.region.sf_config.key_config[n][0] & 0x80)
				MX_INFO(", LinkedCNT: %u",
							(meta.region.sf_config.key_config[n][1] & 0x30) >> 4);
			MX_INFO("\r\n");
		}

		MX_INFO("MC Configurations: \r\n");
		for (n = 0; n < ARMOR_MC_CFG_NUM; n++) {
			MX_INFO("MC   Config %02lu: ", n);
			for (m = 0; m < ARMOR_MC_CFG_SIZE; m++) {
				MX_DBG("%02X", meta.region.sf_config.mc_config[n][m]);
			}
			MX_INFO(" >> MACID: %d, IMACID: %d, OMACID: %d \r\n",
					(meta.region.sf_config.mc_config[n][0] & 0x0C) >> 2,
					(meta.region.sf_config.mc_config[n][1] & 0x03) >> 0,
					(meta.region.sf_config.mc_config[n][1] & 0x30) >> 4);
		}
		MX_INFO("------------------------------------\r\n");
	}
	return status;
}

/*
 * Function:        set_mc
 * Arguments:       mc_id, Monotonic counter ID.
 *                  buf,  A pointer to the buffer that stores the value of monotonic counter.
 * Description:     This function is for setting the counter value.
 */
// int SecureFlashLib::set_mc(uint8_t mc_id, const uint8_t *buf)
// {
//     return _std_program(ARMOR_MC_MEM_ADDR + mc_id * ARMOR_MC_SIZE, buf, ARMOR_MC_SIZE);
// }

/*
 * Function:        get_mc
 * Arguments:       mc_id, Receive the monotonic counter value of the specified ID.
 *                  mc, a pointer to the buffer that receives the monotonic counter value from ArmorFlash.
 * Description:     This function is for reading the counter value.
 */
// int SecureFlashLib::get_mc(uint8_t mc_id, uint8_t *mc)
// {
//     int status = MXST_SUCCESS;
//     uint8_t op = OP_MC_RD;

//     /* read MC is not required IMAC */
//     meta.is_imac_en = FALSE;

//     if (meta.is_omac_en) {
//     	op |= OP_MC_MAC_NEED;

//     	_get_key_id_by_cmd(ARMOR_INST_MC, mc_id, 0);

//     	status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 		if (MXST_SUCCESS != status) {
// 			return status;
// 		}

// 		status = _check_macount();
// 		if (MXST_SUCCESS != status) {
// 			return status;
// 		}
//     }
//     return _armor_mc(mc_id, mc, op);
// }

/*
 * Function:        increase_mc
 * Arguments:       mc_id, Monotonic counter ID.
 *                  mc, a pointer to the buffer that receives the monotonic counter value from ArmorFlash.
 * Description:     This function is for increasing the monotonic counter value.
 */
// int SecureFlashLib::increase_mc(uint8_t mc_id, uint8_t *mc)
// {
//     int status =MXST_SUCCESS;
//     uint8_t op = OP_MC_INCR;

//     status = _check_cmd_permit(ARMOR_INST_MC, mc_id);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* When monotonic counter increment operation is performed, the IMAC needs to be checked. */
// 	meta.is_imac_en = (meta.region.sf_config.mc_config[mc_id][MC_CFG_BYTE_0] & MC_CFG_NEED_MAC_MASK) > 0;

//     if (meta.is_imac_en) {
//     	op |= OP_MC_MAC_NEED;

//     	_get_key_id_by_cmd(ARMOR_INST_MC, mc_id, 0);

//     	status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 		if (status != MXST_SUCCESS) {
// 			return status;
// 		}

// 		status = _check_macount();
// 		if (status != MXST_SUCCESS)
// 			return status;
//     }
//     return _armor_mc(mc_id, mc, op);
// }

/*
 * Function:        sync_mc
 * Arguments:       mc_id,  Monotonic counter ID.
 * Description:     Synchronize the MC values of ArmorFlash and host by the specified MC ID
 */
// void SecureFlashLib::sync_mc(uint8_t mc_id, uint8_t *mc)
// {
//     memcpy(meta.region.mc[mc_id], mc, ARMOR_MC_SIZE);
//     MX_DBG("MC%d: ", mc_id);
// 	for (uint8_t n = 0; n < ARMOR_MC_SIZE; n++)
// 		MX_DBG("%02X", mc[n]);
// 	MX_DBG("\r\n");
// }

/*
 * Function:        get_trng
 * Arguments:       buf, pointer to a buffer where the true random number will be stored.
 *                  size, buffer size.
 *                  rtn_size, The actual random number size of the return.
 * Description:     this function is used to generate random numbers by ArmorFlash.
 */
int SecureFlashLib::get_trng(uint8_t *buf, uint8_t size)
{
	if (NULL == buf) {
		return MXST_BUF_NULL;
	}

	if (meta.is_sf_trng_en)
		MX_DBG("ArmorFlash ConfigLKD register is locked, the RGEN command is enabled\r\n");
	else
		MX_INFO("ArmorFlash ConfigLKD register is un-locked, the RGEN command will generate a fixed pattern\r\n");

	return _armor_rgen(buf, size);
}

/*
 * Function:        get_puf
 * Arguments:       buf,  pointer to a data buffer where the true PUF code will be stored
 *                  size, buffer size.
 *                  rtn_size, The actual PUF code size of the return.
 * Description:     This function is for reading PUF code from ArmorFlash.
 */
// int SecureFlashLib::get_puf(uint8_t *buf, uint8_t size, uint8_t *rtn_size)
// {
//     int status = MXST_SUCCESS;
//     uint8_t puf[ARMOR_PUF_SIZE] = {};

//     MBED_ASSERT(buf);
//     MBED_ASSERT(rtn_size);

//     MX_DBG("ArmorFlash PUF size: %d-bytes, Buffer size: %d-bytes\r\n", ARMOR_PUF_SIZE, size);
//     *rtn_size = ARMOR_PUF_SIZE > size ? size : ARMOR_PUF_SIZE;

//     status = _check_cmd_permit(ARMOR_INST_PUFRD, ARMOR_PUFRD_CBC_KEY_ID);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	_get_key_id_by_cmd(ARMOR_INST_PUFRD, ARMOR_PUFRD_CBC_KEY_ID, 0);

//     status = _check_nonce_random(ARMOR_PUFRD_CBC_KEY_ID);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	status = _check_macount();
// 	if (MXST_SUCCESS != status)
// 		return status;

//     status = _armor_pufrd(puf);
//     if (MXST_SUCCESS != status)
//     	return status;

//     memcpy(buf, puf, *rtn_size);

//     return status;
// }

/*
 * Function:        get_serial_number
 * Arguments:       buf, pointer to a data buffer where the serial number of ArmorFlash will be stored
 *                  size, buffer size.
 *                  rtn_size, The actual serial number size of the return.
 * Return Message:  MXST_SUCCESS.
 *                  MXST_FAILURE.
 *                  MXST_ARMOR_SECURITY_CMD_ERR.
 * Description:     This function is for reading a serial number of ArmorFlash.
 */
void SecureFlashLib::get_serial_number(uint8_t *buf, uint8_t size, uint8_t *rtn_size)
{
	MBED_ASSERT(buf);
	MBED_ASSERT(rtn_size);
	MX_DBG("ArmorFlash serial number size: %d-bytes, Buffer size: %d-bytes\r\n", ARMOR_SN_SIZE, size);
	*rtn_size = ARMOR_SN_SIZE > size ? size : ARMOR_SN_SIZE;
    memcpy(buf, meta.region.sf_config.sn, *rtn_size);
}

int SecureFlashLib::rpmc_prepare_signature_params_root_key(uint8_t *root_key, uint8_t mc_id, uint8_t *msg, uint8_t *key)
{
	
}
int SecureFlashLib::rpmc_write_root_key(uint8_t mc_id, uint8_t *root_key)
{	
	rpmc_packet_t rpmc_packet = {};
	uint8_t truncated_signature[RPMC_WRITE_ROOT_KEY_SIGNATURE_SIZE];
	uint8_t *data_signature = rpmc_packet.data_signature;
	int total_size = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ID_SIZE + RPMC_RESERVED_SIZE + 
			RPMC_ROOT_KEY_SIZE + RPMC_WRITE_ROOT_KEY_SIGNATURE_SIZE;

	rpmc_packet.write.inst = RPMC_INST1;
	rpmc_packet.write.command = 00;
	rpmc_packet.write.mc_id = mc_id;
	memcpy(data_signature, root_key, RPMC_ROOT_KEY_SIZE);
	memcpy(data_signature + RPMC_ROOT_KEY_SIZE, truncated_signature, RPMC_WRITE_ROOT_KEY_SIGNATURE_SIZE);
}
int SecureFlashLib::rpmc_update_hmac_key(uint8_t mc_id, uint8_t *hmac_key_data)
{
	rpmc_packet_t rpmc_packet = {};
	uint8_t signature[RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE];
	uint8_t *data_signature = rpmc_packet.write.data.data_signature;
	int total_size = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ID_SIZE + RPMC_RESERVED_SIZE + 
			HMAC_KEY_DATA_SIZE + RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE;

	rpmc_packet.write.inst = RPMC_INST1;	
	rpmc_packet.write.data.command = 01;
	rpmc_packet.write.data.mc_id = mc_id;

	memcpy(data_signature, hmac_key_data, HMAC_KEY_DATA_SIZE);
	memcpy(data_signature + HMAC_KEY_DATA_SIZE, signature, RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE);
}
int SecureFlashLib::rpmc_request_mc(uint8_t mc_id, uint8_t *mc)
{
	rpmc_packet_t rpmc_packet = {};
	uint8_t signature[RPMC_REQUEST_MC_SIGNATURE_SIZE];
	uint8_t *data_signature = rpmc_packet.data_signature;
	int total_size = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ID_SIZE + RPMC_RESERVED_SIZE + 
			RPMC_TAG_SIZE + RPMC_REQUEST_MC_SIGNATURE_SIZE;

	rpmc_packet.write.inst = RPMC_INST1;
	rpmc_packet.write.command = 01;
	rpmc_packet.write.mc_id = mc_id;
	memcpy(data_signature, hmac_key_data, HMAC_KEY_DATA_SIZE);
	memcpy(data_signature + HMAC_KEY_DATA_SIZE, signature, RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE);
}
int SecureFlashLib::rpmc_increment_mc(uint8_t mc_id, uint8_t *mc)
{
	rpmc_packet_t rpmc_packet = {};
	uint8_t signature[RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE];
	uint8_t *data_signature = rpmc_packet.data_signature;
	int total_size = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ID_SIZE + RPMC_RESERVED_SIZE + 
			RPMC_MC_DATA_SIZE + RPMC_INCREMENT_MC_SIGNATURE_SIZE;

	rpmc_packet.write.inst = RPMC_INST1;
	rpmc_packet.write.command = 02;
	rpmc_packet.write.mc_id = mc_id;
	memcpy(data_signature, hmac_key_data, HMAC_KEY_DATA_SIZE);
	memcpy(data_signature + HMAC_KEY_DATA_SIZE, signature, RPMC_UPDATE_HMAC_KEY_SIGNATURE_SIZE);

	_rpmc_read_status(&rpmc_packet.read);
}

int SecureFlashLib::_rpmc_read_status(rpmc_read_packet_t *read_packet)
{
	read_packet.inst = RPMC_INST2;	
	
}

uint64_t SecureFlashLib::get_density() const
{
    return _security_field_density;
}
uint64_t SecureFlashLib::get_min_erase_size() const
{
    return ERASE_4K;
}
uint64_t SecureFlashLib::get_program_size() const
{
	return ARMOR_DATA_MAX_SIZE;
}
uint64_t SecureFlashLib::get_read_size() const
{
	return ARMOR_DATA_MAX_SIZE;;
}

/****************************/
/* secure flash Functions   */
/****************************/
/*
 * Function:    _internal_write_read_secure_packet
 * Arguments:
 * Description: Write and read secure packets to and from ARMORFLASH
 */
int SecureFlashLib::_internal_write_read_secure_packet(secure_packet_t *secure_packet)
{	
	int status = MXST_SUCCESS;
	uint8_t inst;

	status = _is_mem_ready();
	if (MXST_SUCCESS != status)
		return status;

	status = _check_wren();
	if (MXST_SUCCESS != status)
		return status;	

	/* Packet buffer address reset */
	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_WRITE_4B : STD_INST_SECURE_WRITE;
	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_RESET_ADDR, NULL, 0)) {
		MX_ERR("Write secure packet failed\r\n");
		return MXST_ARMOR_WR_SECURE_PKT_ERR;
	}

	status = _is_mem_ready();
	if (MXST_SUCCESS != status) {
		return status;
	}

	status = _check_wren();
	if (MXST_SUCCESS != status) {
		return status;
	}

	/* compute crc16 for Cmd Packet */
	_compute_crc(_sf_transport.secure_packet.write.count - ARMOR_PKT_CRC_SIZE,
			(uint8_t *)&_sf_transport.secure_packet.write,
			((uint8_t *)&_sf_transport.secure_packet.write) + (_sf_transport.secure_packet.write.count - ARMOR_PKT_CRC_SIZE));

	/* write secure packet through the address : ARMOR_PKT_ADDR*/
	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_WRITE_4B : STD_INST_SECURE_WRITE;
	if (_sf_transport.write_secure_packet(inst, ARMOR_PKT_ADDR, 
			(uint8_t *)&(_sf_transport.secure_packet.write), _sf_transport.secure_packet.write.count)) {
		MX_ERR("Write secure packet failed\r\n");
		return MXST_ARMOR_WR_SECURE_PKT_ERR;
	}

	/* wait for PacketOut/WIP ready */
	status = _is_mem_ready_armor();
	if (MXST_SUCCESS != status) {
		return status;
	}

	status = _check_sr_crc();
	if (MXST_SUCCESS != status) {
		return status;
	}

	/* read secure packet through the address : ARMOR_PKT_ADDR*/
	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_SECURE_READ_4B : STD_INST_SECURE_READ;
    if (_sf_transport.read_secure_packet(inst, ARMOR_PKT_ADDR, 0, 
			(uint8_t *)&_sf_transport.secure_packet.read, sizeof(_sf_transport.secure_packet.read))) {
    	MX_ERR("Read secure packet failed\r\n");
    	return MXST_ARMOR_RD_SECURE_PKT_ERR;
    }

    status = _check_sr_crc();
	if (MXST_SUCCESS != status) {
		return status;
	}

    status = _parse_security_error_code();
    if (MXST_SUCCESS != status) {
        MX_ERR("[ArmorFlash Error Code: %02X], %s\r\n", _sf_transport.secure_packet.read.return_code, meta.rtn_err_msg);
	}

    return status;
}

/*
 * Function:        _get_security_field_info
 * Arguments:       null
 * Description:     This function is for getting all the security field information.
 */
int SecureFlashLib::_get_security_field_info()
{
	int status = MXST_SUCCESS;
	// uint8_t mc[ARMOR_MC_SIZE];

	/* get lock register value */
	MX_DBG("get secure field configurations\r\n");
	status = get_all_sfconfig(NULL, SECURE_FLASH_VERBOSE);
	if (MXST_SUCCESS != status) {
		return status;
	}

//	MX_DBG("get nonce\r\n");
//	status = _get_nonce(NULL);
//
//	if (MXST_SUCCESS != status)
//		return status;
//
//	MX_DBG("get macount\r\n");
//	status = _get_macount();
//	if (MXST_SUCCESS != status)
//		return status;

	// MX_DBG("get MC value\r\n");
	// status = get_mc(MC0, mc);
	// if (MXST_SUCCESS != status)
	// 	return status;
	// status = get_mc(MC1, mc);
	// if (MXST_SUCCESS != status)
	// 	return status;
	// status = get_mc(MC2, mc);
	// if (MXST_SUCCESS != status)
	// 	return status;
	// status = get_mc(MC3, mc);
	// if (MXST_SUCCESS != status)
	// 	return status;
	/* resume OMAC requirement */

	return status;
}

int SecureFlashLib::get_iv(encryption_indicator_t *indicator)
{
	int status = MXST_SUCCESS;
	armor_iv_t iv = {};
	static uint8_t ccm_iv[ARMOR_IV_SIZE + ARMOR_MACOUNT_SIZE] = {};	

	if (NULL == indicator) {
		return MXST_BUF_NULL;
	}

	indicator->aes_ccm_gcm.iv = ccm_iv;
	
	if(ENC_NONE == indicator->aes_ccm_gcm.iv_enc->encryption) {
		status = _get_nonce_from_host(NULL, iv.nonce);
		if (MXST_SUCCESS != status) {
			return status;
		}
	} else {
		memcpy(iv.nonce, indicator->aes_ecb.odata, ARMOR_NONCE_SIZE);		
	}
	status = _get_macount(&iv.macount);
	if (MXST_SUCCESS != status) {
		return status;
	}

	indicator->aes_ccm_gcm.iv_len = ARMOR_NONCE_SIZE + ARMOR_MACOUNT_SIZE;
	memcpy(indicator->aes_ccm_gcm.iv, iv.nonce_tot, ARMOR_NONCE_SIZE + ARMOR_MACOUNT_SIZE);	

	return status;
}

int SecureFlashLib::get_ccm_params(encryption_indicator_t *indicator, command_params_t *cmd_params)
{
    int status = MXST_SUCCESS;

	if (NULL == indicator || NULL == cmd_params) {
		return MXST_BUF_NULL;
	}
	
	status = _prepare_secure_write_packet_base(cmd_params);
	if (MXST_SUCCESS != status) {
		return status;
	}

	status = _get_tag_data(indicator, cmd_params);
	if (MXST_SUCCESS != status) {
		return status;
	}

	status = _get_key(indicator, cmd_params);
	if (MXST_SUCCESS != status) {
		return status;
	}	
	
	status = _get_iv_encryption_params(&indicator->aes_ccm_gcm.iv_enc);
	if (MXST_SUCCESS != status) {
		return status;
	}

	return _get_add(indicator, cmd_params);
}

int SecureFlashLib::_get_tag_data(encryption_indicator_t *indicator, command_params_t *cmd_params)
{
	int status = MXST_SUCCESS;	
	const static uint8_t enc_ers_data[ARMOR_DATA_MAX_SIZE] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		};	

	indicator->aes_ccm_gcm.tag_len = 0;
	indicator->aes_ccm_gcm.data_len = 0;	

	switch (indicator->operation) {
	case OP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV:
	case OP_AUTHEN_TAG_DECRYPT_DATA:
	case OP_AUTHEN_TAG_ENC_IV:
	case OP_AUTHEN_TAG:
		switch (cmd_params->name) {
		case CMDNAME_READ:						
			indicator->aes_ccm_gcm.tag_len = ARMOR_MAC_SIZE;
			indicator->aes_ccm_gcm.tag = cmd_params->read_packet.mac_data_crc;			
			indicator->aes_ccm_gcm.data_len = ARMOR_DATA_MAX_SIZE;			
			indicator->aes_ccm_gcm.idata = cmd_params->read_packet.mac_data_crc + ARMOR_MAC_SIZE;
			indicator->aes_ccm_gcm.odata = cmd_params->odata;
			break;
		case CMDNAME_RD_PUF:			
			indicator->aes_ccm_gcm.tag_len = ARMOR_MAC_SIZE;			
			indicator->aes_ccm_gcm.tag = cmd_params->read_packet.mac_data_crc;
			indicator->aes_ccm_gcm.data_len = ARMOR_PUF_SIZE;			
			indicator->aes_ccm_gcm.idata = cmd_params->read_packet.mac_data_crc + ARMOR_MAC_SIZE;
			indicator->aes_ccm_gcm.odata = cmd_params->odata;
			break;
		default:
			break;
		}

	case OP_ENCRYPT_TAG_DATA_ENC_IV:
	case OP_ENCRYPT_TAG_DATA:
	case OP_ENCRYPT_TAG_ENC_IV:
	case OP_ENCRYPT_TAG:
		switch (cmd_params->name) {
		case CMDNAME_PROGRAM:
			indicator->aes_ccm_gcm.tag_len = ARMOR_MAC_SIZE;
			indicator->aes_ccm_gcm.tag = cmd_params->write_packet.mac_data_crc;
			indicator->aes_ccm_gcm.data_len = ARMOR_DATA_MAX_SIZE;			
			indicator->aes_ccm_gcm.idata = cmd_params->idata;
			indicator->aes_ccm_gcm.odata = cmd_params->write_packet.mac_data_crc + ARMOR_MAC_SIZE;
			break;
		case CMDNAME_ERASE:
			indicator->aes_ccm_gcm.tag_len = ARMOR_MAC_SIZE;
			indicator->aes_ccm_gcm.tag = cmd_params->write_packet.mac_data_crc;
			indicator->aes_ccm_gcm.data_len = ARMOR_DATA_MAX_SIZE;			
			indicatpr->aes_ccm_gcm.idata = enc_ers_data;			
			indicator->aes_ccm_gcm.odata = cmd_params->write_packet.mac_data_crc + ARMOR_MAC_SIZE;
			
			break;
		default:
			break;
		}
	default:
		break;
	}
	return status;
}

int SecureFlashLib::_get_key(encryption_indicator_t *indicator, command_params_t *cmd_params)
{
	int status = MXST_SUCCESS, datazone_id = 0;	
	static uint8_t ccm_key[ARMOR_KEY_SIZE] = {};	

	if (NULL == indicator || NULL == cmd_params) {
		return MXST_BUF_NULL;
	}
	indicator->aes_ccm_gcm.key = ccm_key;

#ifdef DATAZONE_ISOLATION_MODULE
	switch (cmd_params->name) {
	case CMDNAME_READ:
	case CMDNAME_PROGRAM:
	case CMDNAME_ERASE:
		return _get_key_with_datazone_isolation(indicator, cmd_params);
	default:
		break;		
	}
#endif
	
	switch (cmd_params->name) {
	case CMDNAME_READ:
		datazone_id = cmd_params->address / ARMOR_DATAZONE_SIZE;
		meta.cbc_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
		meta.ctr_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_0] & DZ_CFG_RDID_MASK) >> DZ_CFG_RDID_OFS;
		break;
	case CMDNAME_PROGRAM:
		datazone_id = cmd_params->address / ARMOR_DATAZONE_SIZE;
		meta.cbc_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
		meta.ctr_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_WRID_MASK) >> DZ_CFG_WRID_OFS;
		break;
	case CMDNAME_ERASE:
		datazone_id = cmd_params->address / ARMOR_DATAZONE_SIZE;
		meta.cbc_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
		meta.ctr_key_id = (meta.region.sf_config.data_config[datazone_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_WRID_MASK) >> DZ_CFG_WRID_OFS;
		break;
	case CMDNAME_RD_PUF:
		meta.cbc_key_id = DEFAULT_PUFRD_CBC_KEY_ID;
		meta.ctr_key_id = meta.region.sf_config.key_config[DEFAULT_PUFRD_CBC_KEY_ID][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_KEY_MASK;
		break;
	case CMDNAME_RD_MC:
		meta.cbc_key_id = (meta.region.sf_config.mc_config[cmd_params->id][MC_CFG_BYTE_0] & MC_CFG_MACID_MASK) >> MC_CFG_MACID_OFS;
		meta.ctr_key_id = (meta.region.sf_config.mc_config[cmd_params->id][MC_CFG_BYTE_1] & MC_CFG_OMACID_MASK) >> MC_CFG_OMACID_OFS;
		break;
	case CMDNAME_INCR_MC:
		meta.cbc_key_id = (meta.region.sf_config.mc_config[cmd_params->id][MC_CFG_BYTE_0] & MC_CFG_MACID_MASK) >> MC_CFG_MACID_OFS;
		meta.ctr_key_id = (meta.region.sf_config.mc_config[cmd_params->id][MC_CFG_BYTE_1] & MC_CFG_IMACID_MASK) >> MC_CFG_IMACID_OFS;
		break;
	default:
		break;
	}

	meta.linked_mc_id =		
		(meta.region.sf_config.key_config[meta.cbc_key_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_MC_MASK) >> KEY_CFG_LINKED_MC_OFS;
	
	memcpy(indicator->aes_ccm_gcm.key, &meta.region.key[meta.cbc_key_id], ARMOR_KEY_SIZE);
	indicator->aes_ccm_gcm.key_len = ARMOR_KEY_SIZE;
	
	return status;
}

#ifdef DATAZONE_ISOLATION_MODULE
int SecureFlashLib::_get_key_with_datazone_isolation(encryption_indicator_t *indicator, command_params_t *cmd_params)
{	
	int status = MXST_SUCCESS;
	uint8_t datazone_id, n;
	
	if (NULL == indicator) {
		return MXST_BUF_NULL;
	}

	switch (cmd_params->name) {
		case CMDNAME_READ:
		case CMDNAME_PROGRAM:
		case CMDNAME_ERASE:
			datazone_id = cmd_params->address / ARMOR_DATAZONE_SIZE;			
			break;		
		default:		
			return status;
	}

	for (n = 0; n < data_isolation.app_num; n++) {
		if (cmd_params->app_id == data_isolation.app_meta[n].app_id) {
			break;
		}
	}

	/* Check if the APP id has been registerd in provisoining */
	if (n == data_isolation.app_num) {
		return MXST_APP_ID_ERR;
	}		

	/* Check if the APP has permission to operate this datazone id */
	if (datazone_id != data_isolation.app_meta[n].datazone_id) {
		return MXST_APP_ID_ERR;
	}	

	meta.cbc_key_id = data_isolation.app_meta[n].key_id;
	meta.ctr_key_id = data_isolation.app_meta[n].key_id;

	meta.linked_mc_id =		
		(meta.region.sf_config.key_config[meta.cbc_key_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_MC_MASK) >> KEY_CFG_LINKED_MC_OFS;

	memcpy(indicator->aes_ccm_gcm.key, &meta.region.key[meta.cbc_key_id], ARMOR_KEY_SIZE);
	indicator->aes_ccm_gcm.key_len = ARMOR_KEY_SIZE;
}
#endif

int SecureFlashLib::_get_iv_encryption_params(encryption_indicator_t **iv_indicator)
{	
	static encryption_indicator_t indicator = {};	
	static uint8_t ecb_key[ARMOR_KEY_SIZE] = {};
	static uint8_t ecb_idata[ARMOR_DATA_MAX_SIZE] = {};
	static uint8_t ecb_odata[ARMOR_DATA_MAX_SIZE] = {};

	if (NULL == iv_indicator) {
		return MXST_BUF_NULL;
	}
	
	indicator.aes_ecb.idata = ecb_idata;
	indicator.aes_ecb.odata = ecb_odata;
	indicator.aes_ecb.key = ecb_key;	
	*iv_indicator = &indicator;

	return _get_nonce_from_flash(*iv_indicator);
}

/*
 * Function:        _get_nonce_from_host
 * Arguments:       nonce_from_host, the buffer stored NONCE from host.
 * Description:     This function is for generating NONCE and synchronizing it between host and ArmorFlash.
 */
int SecureFlashLib::_get_nonce_from_host(uint8_t* input_nonce, uint8_t *output_nonce)
{
    int status = MXST_SUCCESS;	

	if (NULL == output_nonce) {
		return MXST_BUF_NULL;
	}

	if (NULL == input_nonce) {
		_generate_random_number(output_nonce, ARMOR_NONCE_SIZE);		
	} else {
		memcpy(output_nonce, input_nonce, ARMOR_NONCE_SIZE);
	}	

	status = _armor_ngen(output_nonce, OP_NGEN_FROM_HOST, NULL, 0);
	if (MXST_SUCCESS != status)	{
		return status;
	}
	meta.is_nonce_from_host = TRUE;
	meta.is_nonce_valid = TRUE;

	return status;
}

/*
 * Function:        _get_nonce_from_flash
 * Arguments:       nonce_from_host, the buffer stored NONCE from host.
 * Description:     This function is for generating NONCE and synchronizing it between host and ArmorFlash.
 *                  ArmorFlash can use RGEN to generate a random number as a seed number
 *                  and use NGEN to generate a encrypted NONCE with a seed number,
 *                  then the host need to decrypt the encrypted NONCE and update the NONCE itself.
 */
int SecureFlashLib::_get_nonce_from_flash(encryption_indicator_t *iv_indicator)
{
    int status = MXST_SUCCESS;
    uint8_t in_seed[ARMOR_NONCE_SIZE] = {}, 
			data_for_a[ARMOR_DATA_MAX_SIZE] = {}, 
			key_for_b[ARMOR_KEY_SIZE] = {},
			ngen_data[32] = {};
	
	if (NULL == iv_indicator) {
		return MXST_BUF_NULL;
	}	

	_generate_random_number(in_seed, ARMOR_NONCE_SIZE);	

	status = _armor_ngen(in_seed, OP_NGEN_FROM_FLASH, ngen_data, sizeof(ngen_data));
	if (MXST_SUCCESS != status)
		return status;

	/* Please refer to the specification for the NONCE generating algorithm */

	/* setup data_for_a */
	data_for_a[0] = ARMOR_INST_NGEN;
	data_for_a[1] = OP_NGEN_FROM_FLASH;
	memcpy(data_for_a + 4, in_seed, ARMOR_NONCE_SIZE);

	/* setup key_for_b */
	key_for_b[0] = 0x00;
	key_for_b[1] = MFR_ID_MACRONIX;
	memcpy(key_for_b + 4, ngen_data , 28);

	
	/* configure aes ecb */		
	iv_indicator->aes_ecb.key_len = ARMOR_KEY_SIZE;
	iv_indicator->aes_ecb.data_len = 16;
	iv_indicator->encryption = ENC_AES_ECB_256;
	iv_indicator->operation = ENCOP_ENCRYPT_DATA;	

	/* force parameters of AES ECB to indicator */	
	memcpy(iv_indicator->aes_ecb.key, key_for_b, iv_indicator->aes_ecb.key_len);	
	memcpy(iv_indicator->aes_ecb.idata, data_for_a, iv_indicator->aes_ecb.data_len);

	meta.is_nonce_from_host = FALSE;
	meta.is_nonce_valid = TRUE;

    return status;
}

int SecureFlashLib::_get_add(encryption_indicator_t *indicator, command_params_t *cmd_params)
{	
	int status = MXST_SUCCESS;
	armor_vector_t vector = {};	
	static uint8_t ccm_add[ARMOR_VECTOR_SIZE];	
	
	if (NULL == indicator) {
		return MXST_BUF_NULL;
	}

	memset(ccm_add, 0, ARMOR_VECTOR_SIZE);	
	indicator->aes_ccm_gcm.add = ccm_add;

	/* Configure Vector1 */	
	vector.len = ARMOR_VECTOR1_SIZE - 2;
	vector.mfr_id = MFR_ID_MACRONIX;
	vector.armor_cmd = cmd_params->write_packet.inst;
	vector.op = cmd_params->write_packet.op;
	memcpy(vector.var1, cmd_params->write_packet.var1, ARMOR_VAR1_SIZE);
	memcpy(vector.var2, cmd_params->write_packet.var2, ARMOR_VAR2_SIZE);	
	vector.mac_status = (meta.is_imac_from_host ? 2 : 0) | (meta.is_nonce_from_host ? 0 : 1);

	/* Configure Vector2 */
	if (meta.op_mac_params.buf) {		
		vector.len += ARMOR_VECTOR2_SIZE;
		if (meta.op_mac_params.is_inc_linked_mc)
			memcpy(vector.linked_mc, meta.region.mc[meta.linked_mc_id], ARMOR_MC_SIZE);

		if (meta.op_mac_params.is_inc_sn)
			memcpy(vector.sn, meta.region.sf_config.sn, ARMOR_SN_SIZE);

		if (meta.op_mac_params.is_inc_ext_zone)
			memcpy(vector.ex_zone_4b, meta.region.sf_config.extra_zone, 4);
	}

	memcpy(indicator->aes_ccm_gcm.add, vector.buf + 2, vector.len);
	indicator->aes_ccm_gcm.add_len = vector.len;
	meta.vector_len_tot = vector.len + 2;
	return status;
}

/*
 * Function:        _get_macount
 * Arguments:       null
 * Description:     This function uses INFRD to get the current macount of ArmorFlash.
 */
int SecureFlashLib::_get_macount(uint8_t *macount)
{
    int status = MXST_SUCCESS;

	if (NULL == macount) {
		return MXST_BUF_NULL;
	}

    status = _armor_infrd(ARMOR_INFRD_MACOUNT_ADDR, macount, ARMOR_MACOUNT_SIZE);
	if (MXST_SUCCESS != status) {
		return status;
	}
	(*macount)++;

	return status;
}

/*
 * Function:        _set_sfconfig
 * Arguments:       addr, the secure field configuration address to set.
 *                  buf,  the data buffer stored the configuration value.
 *                  size, the length of configuration value to set.
 * Description:     Set the configuration of security field.
 */
int SecureFlashLib::_set_sfconfig(uint32_t addr, const uint8_t *buf, uint32_t size)
{
	int status = MXST_SUCCESS;
	uint8_t remain = size % ARMOR_DATA_MAX_SIZE;

	while (ARMOR_DATA_MAX_SIZE <= size) {
		status = _std_program(addr, buf, ARMOR_DATA_MAX_SIZE);
		if (MXST_SUCCESS != status)
			return status;
		addr += ARMOR_DATA_MAX_SIZE;
		buf += ARMOR_DATA_MAX_SIZE;
		size -= ARMOR_DATA_MAX_SIZE;
	}
	if (remain) {
		status = _std_program(addr, buf, remain);
		if (MXST_SUCCESS != status)
			return status;
	}
	return status;

	return get_all_sfconfig(NULL, SECURE_FLASH_VERBOSE);
}

/*
 * Function:        _check_macount
 * Arguments:       null
 * Description:     This function is for check the NONCE and macount are valid or not.
 */
// int SecureFlashLib::_check_macount()
// {
// 	int status = MXST_SUCCESS;

//     if (!meta.is_nonce_valid) {
// 		return _get_nonce(NULL);
//     }

// 	status = _get_macount();
// 	if (MXST_SUCCESS != status)
// 		return status;
// 	if (0xFF == _sf_params.encryption.iv.macount || !_sf_params.encryption.iv.macount) {
// 		return  _get_nonce(NULL);
// 	}
//     return status;
// }

/*
 * Function:        _check_nonce_random
 * Arguments:       key_id, the target key id.
 * Description:     This function is for reading key configuration to check if NONCE need to be random.
 */
int SecureFlashLib::_check_nonce_random(uint8_t key_id)
{
    meta.is_nrandom_set = (meta.region.sf_config.key_config[key_id][KEY_CFG_BYTE_3] & KEY_CFG_NRANDOM_MASK) > 0;
	if (meta.is_nrandom_set) {
		if (!meta.is_sf_trng_en) {
			MX_INFO("When the NRANDOM bit is set to 1, the ConfigLKD register must be locked.\r\n");
		}		
	}
	return MXST_SUCCESS;
}

/*
 * Function:        _check_cmd_permit
 * Arguments:       armor_inst, the operation code of ArmorFlash instruction.
 *                  target_id, the id of target data/key/monotonic counter.
 * Description:     This function is for checking if the ArmorFlash command is permit to execute.
 */
int SecureFlashLib::_check_cmd_permit(uint8_t armor_inst, uint8_t target_id)
{
	uint8_t is_permitted;

	switch (armor_inst) {
		case ARMOR_INST_KWR:
			is_permitted = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_2] & KEY_CFG_TARGET_PERM_MASK) > 0;
			if (!is_permitted) {
				MX_ERR("KWR is NOT permitted.\r\n");
				return MXST_ARMOR_KWR_KGEN_NOT_PERM_IN_KEYCFG;
			}
			break;

		case ARMOR_INST_KGEN:
		    is_permitted = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_2] & KEY_CFG_TARGET_PERM_MASK) > 0;
		    if (!is_permitted) {
		    	MX_ERR("KGEN is NOT permitted.\r\n");
		    	return MXST_ARMOR_KWR_KGEN_NOT_PERM_IN_KEYCFG;
		    }
		    break;

		case ARMOR_INST_ENCWR:
			is_permitted = (meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_ENCWR_MASK) > 0;
		    if (!is_permitted) {
		    	MX_ERR("ENCWR is NOT permitted.\r\n");
		    	return MXST_ARMOR_ENWR_NOT_PERM;
		    }
		    break;

		 case ARMOR_INST_PUFRD:
			is_permitted = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_3] & KEY_CFG_PUFRD_PERM_MASK) > 0;
		    if (!is_permitted) {
		    	MX_ERR("PUFRD is NOT permitted.\r\n");
		    	return MXST_ARMOR_PUFRD_NOT_PERM_IN_KEYCFG;
		    }
		    break;

		 case ARMOR_INST_PUFTRANS:
			is_permitted = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_3] & KEY_CFG_PUFTRANS_PERM_MASK) > 0;
			if (!is_permitted) {
				MX_ERR("PUFTRANS is NOT permitted.\r\n");
				return MXST_ARMOR_PUFTRANS_NOT_PERM_IN_KEYCFG;
			}
			break;

		 case ARMOR_INST_MC:
			 is_permitted = (meta.region.sf_config.mc_config[target_id][MC_CFG_BYTE_0] & MC_CFG_INCR_PERM_MASK) > 0;
		    if (!is_permitted) {
		    	MX_ERR("Increment is NOT permitted.\r\n");
		       	return MXST_ARMOR_MC_INCR_NOT_PERM_IN_MCCFG;
		    }
		    break;

		 default:
		    break;
	}
    return MXST_SUCCESS;
}

// int SecureFlashLib::_check_imac_by_cmd(int inst)
// {
// 	switch (inst) {
// 		case ARMOR_INST_ENCRD:
// 			meta.is_imac_from_host = FALSE;
// 			break;
// 		default:
// 			return MXST_ARMOR_INST_ERR;		
// 	}
// 	return MXST_SUCCESS;
// }

/*
 * Function:        _check_key_id_by_cmd
 * Arguments:       armor_inst,  ArmorFlash operation code.
 *                  target_id,  the target id for key_config/data_config/mc_config
 *                  lkd_reg,  indicate the lock target, data zone/individual key.
 * Description:     To get the ctr_key_id, cbc_key_id, linked_mc_id for AES CCM.
 */
int SecureFlashLib::_check_key_id_by_cmd(uint8_t armor_inst, uint8_t target_id, uint8_t lkd_reg)
{
	switch (armor_inst) {
		case ARMOR_INST_KWR:
		case ARMOR_INST_KGEN:
			meta.ctr_key_id = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_KEY_MASK) >> KEY_CFG_LINKED_KEY_OFS;
			meta.cbc_key_id = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_0] & KEY_CFG_MACID_MASK) >> KEY_CFG_MACID_OFS;
			break;
		case ARMOR_INST_ENCRD:
			meta.ctr_key_id = (meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_0] & DZ_CFG_RDID_MASK) >> DZ_CFG_RDID_OFS;
			meta.cbc_key_id = (meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
			break;
		case ARMOR_INST_ENCWR:
			meta.ctr_key_id = meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_WRID_MASK;
			meta.cbc_key_id = (meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
			break;
		case ARMOR_INST_MC:
			if (meta.is_imac_en) {
				meta.ctr_key_id = (meta.region.sf_config.mc_config[target_id][MC_CFG_BYTE_1] & MC_CFG_IMACID_MASK) >> MC_CFG_IMACID_OFS;
			} else {
				meta.ctr_key_id = (meta.region.sf_config.mc_config[target_id][MC_CFG_BYTE_1] & MC_CFG_OMACID_MASK) >> MC_CFG_OMACID_OFS;
			}
			meta.cbc_key_id = (meta.region.sf_config.mc_config[target_id][MC_CFG_BYTE_0] & MC_CFG_MACID_MASK) >> MC_CFG_MACID_OFS;
			break;
		case ARMOR_INST_PUFRD:
			meta.ctr_key_id = meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_KEY_MASK;
			meta.cbc_key_id = target_id;
			break;
		case ARMOR_INST_LKD:
			if (lkd_reg == TARGET_LKD_PUF) {
				meta.ctr_key_id =meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_KEY_MASK;
				meta.cbc_key_id = target_id;
			} else if (lkd_reg == TARGET_LKD_IND_KEY || lkd_reg == TARGET_DIS_IND_KEY) {
				meta.ctr_key_id = meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_KEY_MASK;
				meta.cbc_key_id = (meta.region.sf_config.key_config[target_id][KEY_CFG_BYTE_0] & KEY_CFG_MACID_MASK) >> KEY_CFG_MACID_OFS;
			} else if (lkd_reg == TARGET_LKD_DATAZONE) {
				meta.ctr_key_id = meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_1] & DZ_CFG_WRID_MASK;
				meta.cbc_key_id = (meta.region.sf_config.data_config[target_id][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
			}
			break;
		case ARMOR_INST_PGRD:
		case ARMOR_INST_INFRD:
		case ARMOR_INST_NGEN:
		case ARMOR_INST_RGEN:
		case ARMOR_INST_PUFTRANS:
			break;
		default:
			return MXST_NOT_DEFINED;
	}

	meta.linked_mc_id =
		(meta.region.sf_config.key_config[meta.cbc_key_id][KEY_CFG_BYTE_1] & KEY_CFG_LINKED_MC_MASK) >> KEY_CFG_LINKED_MC_OFS;
	return MXST_SUCCESS;
}

/*
 * Function:        _set_op_by_mac_params
 * Arguments:       op, the option value set by upper layer.
 * Description:     This function is for set the option value of ArmorFlash command.
 */
uint8_t SecureFlashLib::_set_op_by_mac_params(uint8_t inst, uint8_t op)
{
	switch (inst) {
	case ARMOR_INST_KGEN:
	case ARMOR_INST_KWR:
	case ARMOR_INST_ENCRD:
	case ARMOR_INST_ENCWR:
	case ARMOR_INST_MC:
	case ARMOR_INST_LKD:
	case ARMOR_INST_PUFRD:
		op |= meta.op_mac_params.is_inc_linked_mc ? OP_MAC_LINKED_MC : 0;
		op |= meta.op_mac_params.is_inc_sn ? OP_MAC_SN : 0;
		op |= meta.op_mac_params.is_inc_ext_zone ? OP_MAC_EXTRAZONE : 0;
		break;
	default:
		break;
	}
	return op;
}

/*
 * Function:      _parse_security_error_code
 * Arguments:     None
 * Description:   This function is parsed the error code from ArmorFlash.
 */
int SecureFlashLib::_parse_security_error_code(command_params_t *cmd_params)
{
	switch (cmd_params->read_packet.return_code) {
		case ARMOR_RTN_OPERATION_SUCCESS:
			meta.rtn_err_msg =
					"No errors";
			return MXST_SUCCESS;
		case ARMOR_RTN_CMD_ERR:
			meta.rtn_err_msg =
					"Wrong CMD code, wrong option, variable, length, other command error";
			return MXST_ARMOR_RTN_ERR_CODE_CMD;
		case ARMOR_RTN_ADDR_ERR:
			meta.rtn_err_msg =
					"Attempted to Write protected region while Write or address is illegal for this command";
			return MXST_ARMOR_RTN_ERR_CODE_ADD;
		case ARMOR_RTN_BOUNDARY_ERR:
			meta.rtn_err_msg =
					"Crossed a page boundary or wrong byte count in specific mode";
			return MXST_ARMOR_RTN_ERR_CODE_BDRY;
		case ARMOR_RTN_PERM_ERR:
			meta.rtn_err_msg =
					"Attempted to an region which  is not permitted by the configuration";
			return MXST_ARMOR_RTN_ERR_CODE_PERM;
		case ARMOR_RTN_NONCE_ERR:
			meta.rtn_err_msg =
					"Nonce failed or MACount limit has been reached";
			meta.is_nonce_valid = FALSE;
			return MXST_ARMOR_RTN_ERR_CODE_NONCE;
		case ARMOR_RTN_MAC_ERR:
			meta.rtn_err_msg =
					"MAC failed";
			meta.is_nonce_valid = FALSE;
			return MXST_ARMOR_RTN_ERR_CODE_MAC;
		case ARMOR_RTN_CNT_ERR:
			meta.rtn_err_msg =
					"counter error(limit,MAC required ,Increment permitted)";
			return MXST_ARMOR_RTN_ERR_CODE_CNT;
		case ARMOR_RTN_KEY_ERR:
			meta.rtn_err_msg =
					"Wrong key, Key is not permitted to use or other key error";
			return MXST_ARMOR_RTN_ERR_CODE_KEY;
		case ARMOR_RTN_LKD_ERR:
			meta.rtn_err_msg =
					"LKD command contained wrong Checksum or wrong MAC or configuration has not been locked down if required";
			return MXST_ARMOR_RTN_ERR_CODE_LKD;
		case ARMOR_RTN_VFY_ERR:
			meta.rtn_err_msg =
					"data was failed at internal verification";
			return MXST_ARMOR_RTN_ERR_CODE_VFY;
		default:
			meta.rtn_err_msg =
					"This return code is not defined";
			return MXST_ARMOR_RTN_ERR_CODE_NOT_DEF;
	}
}

/*
 * Function:        spi_write_key
 * Arguments:       input_key,     A pointer to the buffer that stores key value
 *                  target_key_id, The key specified by the key ID will be updated.
 * Description:     This function is for updating the key memory by standard SPI program.
 */
int SecureFlashLib::_spi_write_key(uint8_t *input_key, uint8_t target_key_id)
{
	int status = MXST_SUCCESS;

	if (target_key_id > ARMOR_KEY_NUM) {
		MX_ERR("Target key id exceeds the maximum number of keys\r\n");;
		return MXST_ARMOR_SPI_WRITE_KEY_ERR;
	}

	status = _std_program(ARMOR_KEY_MEM_ADDR + target_key_id * ARMOR_KEY_SIZE, input_key, ARMOR_KEY_SIZE);
	if (MXST_SUCCESS != status)
		return status;

	return status;
}

/*
 * Function:        _update_key_by_kwr
 * Arguments:       input_key,     A pointer to the buffer that stores key value
 *                  target_key_id, The key specified by the key ID will be updated.
 * Description:     This function is for updating a key memory by KWR command.
 */
// int SecureFlashLib::_update_key_by_kwr(uint8_t *input_key, uint8_t target_key_id)
// {
//     int status = MXST_SUCCESS;

//     status = _check_cmd_permit(ARMOR_INST_KWR, target_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

// 	_get_key_id_by_cmd(ARMOR_INST_KWR, target_key_id, 0);

//     status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

// 	status = _check_macount();
// 	if ( MXST_SUCCESS != status)
// 		return status;

//     _armor_kwr(target_key_id, input_key, OP_KWR_NVM_KEY);

//     return status;
// }

/*
 * Function:        _update_key_by_kgen
 * Arguments:       target_key_id, The key specified by the key ID will be updated.
 * Description:     This function is for updating a key memory by KGEN command.
 */
// int SecureFlashLib::_update_key_by_kgen(uint8_t target_key_id)
// {
// 	int status = MXST_SUCCESS;

//     status = _check_cmd_permit(ARMOR_INST_KGEN, target_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

//     _get_key_id_by_cmd(ARMOR_INST_KGEN, target_key_id, 0);

//     status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

// 	status = _check_macount();
// 	if ( MXST_SUCCESS != status)
// 		return status;

//     return _armor_kgen(target_key_id, OP_KGEN_NVM_KEY);
// }

/*
 * Function:        _update_key_by_puf
 * Arguments:       target_key_id, The key specified by the key ID will be updated.
 * Description:     This function is for updating a key memory by PUFTRANS command.
 */
// int SecureFlashLib::_update_key_by_puf(uint8_t target_key_id)
// {
//     int status = MXST_SUCCESS;

// //    uint8_t plain_key[ARMOR_KEY_SIZE];

//     status = _check_cmd_permit(ARMOR_INST_PUFRD, ARMOR_PUFRD_CBC_KEY_ID);
// 	if ( MXST_SUCCESS != status)
// 		return status;

//     status = _check_cmd_permit(ARMOR_INST_PUFTRANS, target_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

// 	_get_key_id_by_cmd(ARMOR_INST_PUFRD, ARMOR_PUFRD_CBC_KEY_ID, 0);

//     status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 	if ( MXST_SUCCESS != status)
// 		return status;

// 	status = _check_macount();
// 	if ( MXST_SUCCESS != status)
// 		return status;

//     status = _armor_puftrans(target_key_id);
//     if ( MXST_SUCCESS != status)
//     	return status;

//     return status;
// }

/*
 * Function:        _lock_down
 * Arguments:       lkd_reg,   Lock-down target register.
 *                  idx,       indicate the ID of data zone id or key id.
 * Description:     This function is used to operate the lock register to disable certain operation permission.
 */
// int SecureFlashLib::_lock_down(uint8_t lkd_reg, uint8_t idx)
// {
//     int status = MXST_SUCCESS;

//     meta.is_imac_en = FALSE;

//     /* Check ConfigLkd */
//     switch (lkd_reg) {
// 		case TARGET_LKD_KEY:
// 		case TARGET_LKD_MC:
// 		case TARGET_LKD_PUF:
// 		case TARGET_LKD_DATAZONE:
// 		case TARGET_LKD_IND_KEY:
// 		case TARGET_DIS_IND_KEY:
// 			if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_CONFIG] & ARMOR_LKD_REG_MASK))
// 				MX_INFO("Please lock-down the ConfigLKD register first!\r\n");
// 			break;
// 		default:
// 			break;
//     }

//     switch (lkd_reg) {
// 		case TARGET_LKD_CONFIG:
// 		case TARGET_LKD_KEY:
// 		case TARGET_LKD_EXTRAZONE:
// 		case TARGET_LKD_MC:
// 		case TARGET_LKD_CERS:
// 			idx = 0;
// 			break;
// 		case TARGET_LKD_PUF:
// 			if (ARMOR_LKD_REG_NOT_LKD == (meta.region.sf_config.lock_reg[TARGET_LKD_PUF] & ARMOR_LKD_REG_MASK)) {
// 				meta.is_imac_en = TRUE;
// 				_sf_params.encryption.cbc_key_id = idx;
// 			} else {
// 				MX_DBG("PUFRD and PUFTRANS commands have been locked\r\n");
// 				return MXST_SUCCESS;
// 			}
// 			break;
// 		case TARGET_LKD_DATAZONE:
// 		{
// 			uint8_t write_perm = meta.region.sf_config.data_config[idx][DATAZONE_CFG_BYTE_2] & DZ_CFG_WRITE_PERM_MASK;
// 			uint8_t write_lkd = ((meta.region.sf_config.data_config[idx][DATAZONE_CFG_BYTE_3] & DZ_CFG_WRITE_LKD_MARK) >> DZ_CFG_WRITE_LKD_OFS);
// 			/* Check write operation is inhibited or not */
// 			if (DZ_CFG_WRITE_PERM_INHIBIT == write_perm) {
// 				MX_DBG("Data Zone %d has been locked\r\n", idx);
// 				return MXST_SUCCESS;
// 			}

// 			/* Check if the write operation is determined by the WriteLKD register */
// 			if (DZ_CFG_WRITE_PERM_LKD_WO_IMAC == write_perm || DZ_CFG_WRITE_PERM_LKD_W_IMAC == write_perm) {
// 				if (ARMOR_LKD_REG_NOT_LKD == write_lkd) {
// 					if (DZ_CFG_WRITE_PERM_LKD_W_IMAC == write_perm) {
// 						meta.is_imac_en = TRUE;
// 						_sf_params.encryption.cbc_key_id =
// 								(meta.region.sf_config.data_config[idx][DATAZONE_CFG_BYTE_2] & DZ_CFG_MACID_MASK) >> DZ_CFG_MACID_OFS;
// 					}
// 				} else {
// 					MX_DBG("Data Zone %d has been locked\r\n", idx);
// 					return MXST_SUCCESS;
// 				}
// 			}
// 			break;
// 		}
// 		case TARGET_LKD_IND_KEY:
// 			if (KEY_CFG_IND_NOT_LKD != (meta.region.sf_config.key_config[idx][KEY_CFG_BYTE_3] & KEY_CFG_IND_LKD_MASK)) {
// 				MX_DBG("Key %d has been locked\r\n", idx);
// 		        return MXST_SUCCESS;
// 			}
// 			meta.is_imac_en = TRUE;
// 			_sf_params.encryption.cbc_key_id = (meta.region.sf_config.key_config[idx][KEY_CFG_BYTE_0] & KEY_CFG_MACID_MASK) >> KEY_CFG_MACID_OFS;
// 			break;
// 		case TARGET_DIS_IND_KEY:
//             if (KEY_CFG_IND_NOT_DIS != (meta.region.sf_config.key_config[idx][KEY_CFG_BYTE_3] & KEY_CFG_IND_DIS_MASK)) {
//             	MX_DBG("Key %d has been disabled\r\n", idx);
// 		        return MXST_SUCCESS;
//             }
// 			meta.is_imac_en = TRUE;
// 			_sf_params.encryption.cbc_key_id = (meta.region.sf_config.key_config[idx][KEY_CFG_BYTE_0] & KEY_CFG_MACID_MASK) >> KEY_CFG_MACID_OFS;
// 			break;
// 		default:
// 			break;
//     }

//     if (meta.is_imac_en) {
//     	status = _check_nonce_random(_sf_params.encryption.cbc_key_id);
// 		if (MXST_SUCCESS != status)
// 			return status;
// 		status = _check_macount();
// 		if (MXST_SUCCESS != status)
// 			return status;
//     }

//     return _armor_lkd(idx, lkd_reg);
// }

/****************************/
/* secure flash Commands    */
/****************************/

/*
 * Function:        _armor_encrd
 * Arguments:       addr, The address of data memory to read.
 *                  size, The length of read data.
 *                  buf,  A poniter to the read data(.
 *                  op,   the option value of command.
 * Description:     The ENCRD command is used to encrypt data from data memory and output encrypted data and MAC.
 */
// int SecureFlashLib::_armor_encrd(uint32_t addr, uint8_t *buf, uint32_t size)
// {
// 	int status = MXST_SUCCESS;

// 	meta.is_imac_en = FALSE;

// 	_sf_transport.secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;
// 	_sf_transport.secure_packet.write.inst = ARMOR_INST_ENCRD;
// 	_sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_ENCRD, 0);
// 	_sf_transport.secure_packet.write.var1[0] = (addr >> 16);
// 	_sf_transport.secure_packet.write.var1[1] = (addr >> 8);
// 	_sf_transport.secure_packet.write.var1[2] = (addr >> 0);
// 	_sf_transport.secure_packet.write.var2[0] = 0;
// 	_sf_transport.secure_packet.write.var2[1] = size;

// 	/* write write/read secure packet through the address: ARMOR_PKT_ADDR */
// 	status = _internal_write_read_secure_packet();
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	/* get OMAC */
// 	memcpy(_sf_params.encryption.mac, _sf_params.rd_secure_pkt.mac_data, ARMOR_MAC_SIZE);

// 	/* prepare the parameters of AES CCM for decryption */
// 	_get_aes_ccm_params(_sf_params.rd_secure_pkt.mac_data + ARMOR_MAC_SIZE, AUTHEN_MAC_DECRYPT_DATA);

// 	return status;
// }

/*
 * Function:        _armor_encwr
 * Arguments:       addr, The address of data memory to write or erase.
 *                  buf,  Data buffer stored data to write or erase.
 *                  size, The  length of program data.
 *                  op,   The option value of command.
 * Description:     The ENCWR command is used to decrypt ciphertext data and program or erase into the data memory after verifying the IMAC.
 */
// void SecureFlashLib::_armor_encwr(uint32_t addr, const uint8_t *buf, uint8_t size, uint8_t op)
// {
//     meta.is_imac_en = TRUE;

//     _sf_transport.secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + ARMOR_MAC_SIZE + size;

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_ENCWR;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_ENCWR, op);
//     _sf_transport.secure_packet.write.var1[0] = (addr >> 16);
//     _sf_transport.secure_packet.write.var1[1] = (addr >> 8);
//     _sf_transport.secure_packet.write.var1[2] = (addr >> 0);

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = size;

//     /* prepare the parameters of AES CCM for encryption */
//      _get_aes_ccm_params(buf, ENCRYPT_MAC_DATA);
// }

/*
 * Function:        _armor_kwr
 * Arguments:       target_key_id, the target key ID.
 *                  input_key,     A pointer to the buffer that stores the input Key value.
 *                  op,            the option value of command.
 * Description:     The KWR command is used to decrypt 32 bytes of ciphertext data,
 *                  verifies the MAC, and then writes the plaintext into NVM key region.
 */
// void SecureFlashLib::_armor_kwr(uint8_t target_key_id, uint8_t *input_key, uint8_t op)
// {
//     meta.is_imac_en = TRUE;
//     _sf_transport.secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + ARMOR_MAC_SIZE + ARMOR_KEY_SIZE;

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_KWR;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_KWR, op);
//     _sf_transport.secure_packet.write.var1[0] = 0;
//     _sf_transport.secure_packet.write.var1[1] = target_key_id;
//     _sf_transport.secure_packet.write.var1[2] = 0;

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = 0;

//     /* prepare the parameters of AES CCM for encryption */
//     _get_aes_ccm_params(input_key, ENCRYPT_MAC_KEY);
// }

/*
 * Function:        _armor_kgen
 * Arguments:       target_key_id, the target key ID.
 *                  op,            the option value of command.
 * Description:     The KGEN command is used to generate a 32-bytes random number as a NVM key.
 *                  The key is then encrypted with the CTR key, then output the ciphertext key key data and MAC to the host.
 */
// int SecureFlashLib::_armor_kgen(uint8_t target_key_id, uint8_t op)
// {
// 	int status = MXST_SUCCESS;
//     uint8_t key[ARMOR_KEY_SIZE] = {};

//     meta.is_imac_en =
//     		(meta.region.sf_config.key_config[target_key_id][KEY_CFG_BYTE_0] & KEY_CFG_KGEN_MAC_MASK) > 0;

//     _sf_transport.secure_packet.write.count =
//     		ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + (meta.is_imac_en ? ARMOR_MAC_SIZE : 0);

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_KGEN;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_KGEN, op);
//     _sf_transport.secure_packet.write.var1[0] = 0;
//     _sf_transport.secure_packet.write.var1[1] = target_key_id;
//     _sf_transport.secure_packet.write.var1[2] = 0;

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = 0;

//     if (meta.is_imac_en) {
//     	_get_aes_ccm_params(NULL, ENCRYPT_MAC);
//     	/* set macount and is_imac_en for host to calculate and compare OMAC  */
//     	_sf_params.encryption.iv.macount += 1;
//     	meta.is_imac_en = FALSE;
//     	return status;
//     }

//     /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
//     status = _internal_write_read_secure_packet();
//     if ( MXST_SUCCESS != status)
//     	return status;

//     /* get cipher MAC */
//     memcpy(_sf_params.encryption.mac, _sf_params.rd_secure_pkt.mac_data , ARMOR_MAC_SIZE);
//     /* get cipher key */
//     memcpy(key, _sf_params.rd_secure_pkt.mac_data + ARMOR_MAC_SIZE, ARMOR_KEY_SIZE);

//     _get_aes_ccm_params(key, AUTHEN_MAC_DECRYPT_KEY);

//     return status;
// }

/*
 * Function:        _armor_lkd
 * Arguments:       target_id, indicate the ID of data and key and CbcKey ID of PUF
 *                  op,        the option value of command.
 * Description:     The LKD command is used to lock the configuration memory, key memory, extra zone, etc.
 */
// int SecureFlashLib::_armor_lkd(uint8_t target_id, uint8_t op)
// {
//     _sf_transport.secure_packet.write.count =
//     		ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + (meta.is_imac_en ? ARMOR_MAC_SIZE : 0);

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_LKD;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_LKD, op);
//     _sf_transport.secure_packet.write.var1[0] = 0;
//     _sf_transport.secure_packet.write.var1[1] = target_id;
//     _sf_transport.secure_packet.write.var1[2] = 0;

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = 0;

//     if (meta.is_imac_en) {
//     	_get_aes_ccm_params(NULL, ENCRYPT_MAC);
//     	return MXST_SUCCESS;
//     }

//     memset(&security_data, 0, sizeof (security_data));
//     /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
//     return _internal_write_read_secure_packet();
// }

/*
 * Function:        armor_pufrd
 * Arguments:       cbc_key_id, the CBC key id.
 *                  buf,  point to a buffer of PUF code.
 *                  size, buffer size.
 * Description:     The PUFRD command is used to read PUF code from PUFWL and output in ciphertext.
 */
// int SecureFlashLib::_armor_pufrd(uint8_t *buf)
// {
// 	int status = MXST_SUCCESS;

//     MBED_ASSERT(buf);

//     meta.is_imac_en = FALSE;

//     _sf_transport.secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_PUFRD;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_PUFRD, 0);
//     _sf_transport.secure_packet.write.var1[0] = 0;
//     _sf_transport.secure_packet.write.var1[1] = _sf_params.encryption.cbc_key_id;
//     _sf_transport.secure_packet.write.var1[2] = 0;

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = 0;

//     /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
//     status = _internal_write_read_secure_packet();
//     if (MXST_SUCCESS != status)
//     	return status;

//     /* get the ciphertext MAC */
//     memcpy(_sf_params.encryption.mac, _sf_params.rd_secure_pkt.mac_data, ARMOR_MAC_SIZE);
// 	/* get the ciphertext PUF code */
// 	memcpy(buf, _sf_params.rd_secure_pkt.mac_data + ARMOR_MAC_SIZE, ARMOR_PUF_SIZE);

//     _get_aes_ccm_params(buf, AUTHEN_MAC_DECRYPT_DATA);
//     return status;
// }

/*
 * Function:        _armor_mc
 * Arguments:       target_mc_id, the monotonic counter ID.
 *                  op,           the option value of command.
 * Description:     The MC command is used to increase or read the designed monotonic counter(key used counter).
 */
// int SecureFlashLib::_armor_mc(uint8_t target_mc_id, uint8_t *mc, uint8_t op)
// {
// 	int status = MXST_SUCCESS;
//     uint8_t is_omac_need;


//     switch (op & OP_MC_INCR_RD_MASK) {
//     /* increment monotonic counter */
//     case OP_MC_INCR:
//     	meta.is_imac_en = (op & OP_MC_MAC_NEED) > 0;
//     	is_omac_need = FALSE;
//     	MX_DBG("INCR MC, imac_en: %d, omac_en: %d\r\n", meta.is_imac_en, is_omac_need);
//     	break;
//     /* read monotonic counter */
//     case OP_MC_RD:
//     	meta.is_imac_en = FALSE;
// 		is_omac_need = (op & OP_MC_MAC_NEED) > 0;
// 		MX_DBG("READ MC, imac_en: %d, omac_en: %d\r\n", meta.is_imac_en, is_omac_need);
// 		break;
//     default:
//     	return MXST_NOT_DEFINED;
//     }

//     _sf_transport.secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + (meta.is_imac_en ? ARMOR_MAC_SIZE : 0);

//     _sf_transport.secure_packet.write.inst = ARMOR_INST_MC;
//     _sf_transport.secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_MC, op);
//     _sf_transport.secure_packet.write.var1[0] = 0;
//     _sf_transport.secure_packet.write.var1[1] = target_mc_id;
//     _sf_transport.secure_packet.write.var1[2] = 0;

//     _sf_transport.secure_packet.write.var2[0] = 0;
//     _sf_transport.secure_packet.write.var2[1] = 0;

//     /* prepare the parameters for generating IMAC */
//     if (meta.is_imac_en) {
//     	_get_aes_ccm_params(NULL, ENCRYPT_MAC);
//     	return status;
//     }

//     /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
//     status = _internal_write_read_secure_packet();
//     if (MXST_SUCCESS != status)
//     	return status;

//     if (is_omac_need) {
//     	/* get OMAC */
//     	memcpy(_sf_params.encryption.mac, _sf_params.rd_secure_pkt.mac_data, ARMOR_MAC_SIZE);
//     	/* get monotonic counter */
//     	memcpy(mc, _sf_params.rd_secure_pkt.mac_data + ARMOR_MAC_SIZE, ARMOR_MC_SIZE);

//     	_get_aes_ccm_params(NULL, AUTHEN_MAC);
//     	return status;
//     }

//     /* If MC operation does not require IMAC and OMAC */
//     _get_aes_ccm_params(NULL, NO_SECURITY_OPERATION);
//     memcpy(&meta.region.mc[target_mc_id], _sf_params.rd_secure_pkt.mac_data, ARMOR_MC_SIZE);
//     memcpy(mc, _sf_params.rd_secure_pkt.mac_data, ARMOR_MC_SIZE);
//     return status;
// }

/*
 * Function:        _armor_pgrd
 * Arguments:       addr,       the address of data memory or the configuration memory.
 *                  buf,        the buffer of read data.
 *                  size,       the length of read data.
 * Description:     The PGRD command is used to read 1 to 32 bytes of plaintext data from a data zone or the configuration memory.
 */
int SecureFlashLib::_armor_pgrd(uint32_t addr, uint8_t *buf, uint8_t size)
{
	int status = MXST_SUCCESS;
	secure_packet_t secure_packet;

    secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;
 
    secure_packet.write.inst = ARMOR_INST_PGRD;
    secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_PGRD, 0);
    secure_packet.write.var1[0] = (addr >> 16);
    secure_packet.write.var1[1] = (addr >> 8);
    secure_packet.write.var1[2] = (addr >> 0);
 
    secure_packet.write.var2[0] = 0;
    secure_packet.write.var2[1] = (size >> 0);
 
    /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
    status = _internal_write_read_secure_packet(&secure_packet);
    if (MXST_SUCCESS != status)
    	return status;
    memcpy(buf, secure_packet.read.mac_data_crc, size);
 
    return status;
}

/*
 * Function:        _armor_rgen
 * Arguments:       buf,  point to a buffer of true random number generator.
 *                  size, buffer size.
 * Description:     The RGEN command is to generate the random number by random number generator that embedded in the ArmorFlash.
 */
int SecureFlashLib::_armor_rgen(uint8_t *buf, uint8_t size)
{
	int status = MXST_SUCCESS;
	secure_packet_t secure_packet = {};

    _secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;

    secure_packet.write.inst = ARMOR_INST_RGEN;
    secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_RGEN, 0);
    secure_packet.write.var1[0] = 0;
    secure_packet.write.var1[1] = 0;
    secure_packet.write.var1[2] = 0;

    secure_packet.write.var2[0] = 0;
    secure_packet.write.var2[1] = 0;

    /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
    status = _internal_write_read_secure_packet(&secure_packet);
    if (MXST_SUCCESS != status)
    	return status;
    memcpy(buf, _sf_params.rd_secure_pkt.mac_data, ARMOR_TRNG_SIZE < size ? ARMOR_TRNG_SIZE : size);

    return status;
}

/*
 * Function:        _armor_ngen
 * Arguments:       in_data, data buffer stored 12 bytes input data for loading to Nonce register or generating Nonce value.
 *                  op,      the option value of command.
 * Description:     The NGEN command is to store the internal generated or user-entered random number into Nonce register.
 */
int SecureFlashLib::_armor_ngen(uint8_t *in_data, uint8_t op, uint8_t *output_data, uint8_t size)
{
	int status = MXST_SUCCESS;
	uint8_t ngen_size = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA - (ARMOR_PKT_COUNT_SIZE + ARMOR_PKT_RTN_CODE_SIZE + ARMOR_PKT_CRC_SIZE);
	secure_packet_t secure_packet = {};	

    secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA + ARMOR_NONCE_SIZE;

    secure_packet.write.inst = ARMOR_INST_NGEN;
    secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_NGEN, op);
    secure_packet.write.var1[0] = 0;
    secure_packet.write.var1[1] = 0;
    secure_packet.write.var1[2] = 0;

    secure_packet.write.var2[0] = 0;
    secure_packet.write.var2[1] = 0;

    memcpy(secure_packet.write.mac_data_crc, in_data, ARMOR_NONCE_SIZE);

    /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
    status = _internal_write_read_secure_packet(&secure_packet);
	if (MXST_SUCCESS != status) {
		return status;
	}

	if (OP_NGEN_FROM_FLASH == op && NULL != output_data) {
		memcpy(output_data, secure_packet.read.mac_data_crc + ARMOR_PKT_COUNT_SIZE + ARMOR_PKT_RTN_CODE_SIZE, 
			size > ngen_size ? ngen_size : size);
	}
	return status;
}

/*
 * Function:        _armor_infrd
 * Arguments:       addr, the address of register to read.
 * Description:     The INFRD command is used to read device information.
 */
int SecureFlashLib::_armor_infrd(uint32_t addr, uint8_t *output_data, uint8_t size)
{
	int status = MXST_SUCCESS;
	secure_packet_t secure_packet = {};

	if (NULL == output_data) {
		return MXST_BUF_NULL;
	}

    secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;

    secure_packet.write.inst = ARMOR_INST_INFRD;
    secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_INFRD, 0);
    secure_packet.write.var1[0] = (addr >> 16);
    secure_packet.write.var1[1] = (addr >> 8);
    secure_packet.write.var1[2] = (addr >> 0);

    secure_packet.write.var2[0] = 0;
    secure_packet.write.var2[1] = 0;

    /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
    status = _internal_write_read_secure_packet(&secure_packet);
	if (MXST_SUCCESS != status) {
		return status;
	}

	memcpy(output_data, secure_packet.read.mac_data_crc, size > ARMOR_MACOUNT_SIZE ? ARMOR_MACOUNT_SIZE : size);
	return status;
}

/*
 * Function:        armor_puftrans
 *                  key_id, Update the specified KEY with PUF code by key ID.
 * Description:     The PUFTRANS command is used to transfer internal PUF code into a key.
 */
int SecureFlashLib::_armor_puftrans(uint8_t key_id)
{
	secure_packet_t secure_packet = {};

	secure_packet.write.count = ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA;

	secure_packet.write.inst = ARMOR_INST_PUFTRANS;
	secure_packet.write.op = _set_op_by_mac_params(ARMOR_INST_PUFTRANS, 0);
	secure_packet.write.var1[0] = 0;
	secure_packet.write.var1[1] = key_id;
	secure_packet.write.var1[2] = 0;

	secure_packet.write.var2[0] = 0;
	secure_packet.write.var2[1] = 0;

    /* write write/read secure packet through the address : ARMOR_PKT_ADDR */
    return _internal_write_read_secure_packet(&secure_packet);
}

/********************************/
/* standard NOR flash functions */
/********************************/
int SecureFlashLib::_std_wren()
{
	if (_sf_transport.send_general_command(STD_INST_WREN, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Send WREN failed\r\n");
		return MXST_SEND_CMD_ERR;
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_program(uint32_t addr, const uint8_t *buf, uint8_t size)
{
    int status = MXST_SUCCESS;
    uint8_t inst;

    status = _std_wren();
    if (MXST_SUCCESS != status) {
    	return status;
    }

	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_PP_4B : STD_INST_PP;
    status =  _sf_transport.send_program_command(inst, addr, buf, size);
    if (MXST_SUCCESS != status) {
    	MX_ERR("send program command*(%02X) failed\r\n", inst);
        return MXST_SEND_CMD_ERR;
    }

    /* wait for WIP ready */
    return _is_mem_ready();
}

int SecureFlashLib::_std_read(uint32_t addr, uint8_t *buf, uint8_t size)
{
    uint8_t inst;

	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_READ_4B : STD_INST_READ;
    if ( _sf_transport.send_read_command(inst, addr, buf, size)) {
    	MX_ERR("send read command*(%02X) failed\r\n", inst);
        return MXST_SEND_CMD_ERR;
    }

    return MXST_SUCCESS;
}

int SecureFlashLib::_std_erase(uint32_t addr, uint8_t size)
{
	int status = MXST_SUCCESS;
    uint8_t inst;

	status = _std_wren();
	if (MXST_SUCCESS != status)
		return status;

	inst = (4 == _sf_transport.flash_protocol.addr_len) ? STD_INST_ERASE_4K_4B : STD_INST_ERASE_4K;
    status =  _sf_transport.send_erase_command(inst, addr, size);
    if (MXST_SUCCESS != status) {
    	MX_ERR("send erase command*(%02X) failed\r\n", inst);
        return MXST_SEND_CMD_ERR;
    }

    /* wait for WIP ready */
    return _is_mem_ready();
}

int SecureFlashLib::_std_read_sr(uint8_t *status_reg, uint8_t size)
{
	if (_sf_transport.send_general_command(STD_INST_RDSR, 0, 0, 0, NULL, 0, status_reg, size)) {
		MX_ERR("Read Status Register failed\r\n");
		return MXST_SEND_CMD_ERR;
	}
	return MXST_SUCCESS;
}
int SecureFlashLib::_std_read_scur(uint8_t *secure_reg, uint8_t size)
{
	if (_sf_transport.send_general_command(STD_INST_RDSCUR, 0, 0, 0, NULL, 0, secure_reg, size)) {
		MX_ERR("Reading Secure Register failed\r\n");
		return MXST_SEND_CMD_ERR;
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_read_cr(uint8_t *configuration_reg, uint8_t size)
{
	if (_sf_transport.send_general_command(STD_INST_RDCR, 0, 0, 0, NULL, 0, configuration_reg, size)) {
		MX_ERR("Reading Configuration_reg Register failed\r\n");
		return MXST_SEND_CMD_ERR;
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_read_id(uint8_t *id, uint8_t size)
{
    if (_sf_transport.send_general_command(STD_INST_RDID, 0, 0, 0, NULL, 0, id, size)) {
    	MX_ERR("Read ID failed\r\n");
        return MXST_SEND_CMD_ERR;
    }
    return MXST_SUCCESS;
}

int SecureFlashLib::_std_ensf()
{
	if (_sf_transport.send_general_command(STD_INST_ENSF, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Send ENSF failed\r\n");
	    return MXST_SEND_CMD_ERR;
	}
	MX_ERR("Send ENSF success\r\n");
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_exsf()
{
	if (_sf_transport.send_general_command(STD_INST_EXSF, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Send EXSF failed\r\n");
	    return MXST_SEND_CMD_ERR;
	}
	MX_DBG("Send EXSF success\r\n");
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_sw_reset()
{
	MX_DBG(" S/W Reset");

	if (_sf_transport.send_general_command(STD_INST_RSTEN, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Sending RSTEN failed\r\n");
		return MXST_SEND_CMD_ERR;
	} else {
		MX_DBG("Sending RSTEN Success");
	}

	if (_sf_transport.send_general_command(STD_INST_RST, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Sending RST failed\r\n");
		return MXST_SEND_CMD_ERR;
	} else {
		MX_DBG("Sending RST Success\r\n");
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_std_en4b()
{
	int status = MXST_SUCCESS;
	uint8_t cr;

	MX_DBG("Enable 4-bytes address mode\r\n");
	if (_sf_transport.send_general_command(STD_INST_EN4B, 0, 0, 0, NULL, 0, NULL, 0)) {
		MX_ERR("Sending EN4B failed\r\n");
		return MXST_SEND_CMD_ERR;
	} else {
		MX_DBG("Sending EN4B Success\r\n");
	}

	status = _std_read_cr(&cr, 1);
	if (MXST_SUCCESS != status)
		return status;

	if (cr & CR_BIT_4BEN) {
		MX_DBG("configuration register(%02X), change to EN4B mode is successful\r\n", cr);
		_sf_transport.flash_protocol.addr_len = 4;
	} else {
		MX_INFO("configuration register(%02X), change to EN4B mode is failed\r\n", cr);
		_sf_transport.flash_protocol.addr_len = 3;
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_is_mem_ready()
{
	int status = MXST_SUCCESS, retries = 0;
    uint8_t status_reg;
    

    do {
//        rtos::ThisThread::sleep_for(1ms);
        retries++;
        status = _std_read_sr(&status_reg, 1);
        if (MXST_SUCCESS != status)
            return status;
    } while ((status_reg & SR_BIT_WIP) != 0 && retries < IS_MEM_READY_MAX_RETRIES);

    if ((status_reg & SR_BIT_WIP) != 0) {
        MX_ERR("time out, Flash is busy\r\n");
        return MXST_FLASH_NOT_READY;
    }
    return MXST_SUCCESS;
}

int SecureFlashLib::_is_mem_ready_armor()
{
	int status = MXST_SUCCESS, retries = 0;
	uint8_t status_reg;
	
	/* Polling for security packet readiness from ArmorFlash. */
	do {
		retries++;
		status = _std_read_sr(&status_reg, 1);
		if (MXST_SUCCESS != status)
			return status;
	} while ((!(status_reg & SF_SR_BIT_OUT_RDY) || (status_reg & SF_SR_BIT_WIP)) && retries < IS_MEM_READY_MAX_RETRIES);

	if (!(status_reg & SF_SR_BIT_OUT_RDY) || status_reg & SF_SR_BIT_WIP) {
		MX_ERR("time out, ArmorFlash is busy\r\n");
		return MXST_FLASH_NOT_READY;
	}
	return MXST_SUCCESS;
}

int SecureFlashLib::_check_wren()
{
	int status = MXST_SUCCESS;
	uint8_t status_reg;

	status = _std_wren();
	if (MXST_SUCCESS != status) {
		return status;
	}

	/* Check WEL bit in status register */
	status = _std_read_sr(&status_reg, 1);
	if (MXST_SUCCESS != status || !(status_reg & SF_SR_BIT_WEL)) {
		MX_ERR("set WREN failed, status register: %02X\r\n", status_reg);
		return MXST_WREN_ERR;
	}
	return status;
}

int SecureFlashLib::_check_sr_crc()
{
	int status = MXST_SUCCESS;
	uint8_t status_reg;

	status = _std_read_sr(&status_reg, 1);
	if (MXST_SUCCESS != status) {
		return status;
	}
    if (status_reg & SF_SR_BIT_CRC_ERR) {
    	MX_ERR("CRC error after sending secure packet!, status reg: %02X\r\n", status_reg);
    	return MXST_CRC_ERR;
    }
    return status;
}

/*******************/
/* Other functions */
/*******************/
void SecureFlashLib::_compute_crc(uint8_t data_len, uint8_t *data_buf, uint8_t* rtn_crc)
{
	uint8_t crc_low = 0, crc_high = 0, poly_low = 0x05, poly_high = 0x80, cnt = 0;
	uint8_t crc_carry, crc_bit, data_bit, shift_bit;

	while (data_len > cnt) {
		shift_bit = 0x80;
		while (shift_bit) {
			data_bit = (data_buf[cnt] & shift_bit) ? 1 : 0;
			crc_bit = crc_high >> 7;
			crc_carry = crc_low >> 7;
			crc_low <<= 1;
			crc_high <<= 1;
			crc_high |= crc_carry;

			if (data_bit ^ crc_bit) {
				crc_low ^= poly_low;
				crc_high ^= poly_high;
			}
			shift_bit >>= 1;
		}
		cnt++;
	}
	rtn_crc[0] = crc_high;
	rtn_crc[1] = crc_low;
}

// void SecureFlashLib::_get_vector()
// {	
// 	_sf_params.encryption.vector_len_tot = ARMOR_VECTOR1_SIZE;
// 	_sf_params.encryption.is_imac_from_host = meta.is_imac_en;

// 	memset(_sf_params.encryption.vector.buf, 0, sizeof(_sf_params.encryption.vector.buf));	

// 	/* Vector1 */
// 	_sf_params.encryption.vector.vector_len = ARMOR_VECTOR1_SIZE - 2;
// 	_sf_params.encryption.vector.mfr_id = MFR_ID_MACRONIX;
// 	_sf_params.encryption.vector.armor_cmd = _sf_transport.secure_packet.write.inst;
// 	_sf_params.encryption.vector.op = _sf_transport.secure_packet.write.op;
// 	memcpy(_sf_params.encryption.vector.var1, _sf_transport.secure_packet.write.var1, ARMOR_VAR1_SIZE);
// 	memcpy(_sf_params.encryption.vector.var2, _sf_transport.secure_packet.write.var2, ARMOR_VAR2_SIZE);
// 	_sf_params.encryption.vector.mac_status =
// 		(_sf_params.encryption.is_imac_from_host ? 2 : 0) | (_sf_params.encryption.is_nonce_from_host ? 0 : 1);

// 	if (ARMOR_INST_MC == _sf_transport.secure_packet.write.inst) {
// 		memcpy(_sf_params.encryption.vector.reserved_mc,
// 				meta.region.mc[_sf_transport.secure_packet.write.var1[1]], ARMOR_MC_SIZE);
// 	}

// 	/* Vector2 */
// 	if (_sf_params.encryption.op_mac_params.inc_mac_params) {

// 		_sf_params.encryption.vector.vector_len += ARMOR_VECTOR2_SIZE;
// 		_sf_params.encryption.vector_len_tot += ARMOR_VECTOR2_SIZE;

// 		if (_sf_params.encryption.op_mac_params.is_inc_linked_mc)
// 			memcpy(_sf_params.encryption.vector.linked_mc,
// 					meta.region.mc[_sf_params.encryption.linked_mc_id], ARMOR_MC_SIZE);

// 		if (_sf_params.encryption.op_mac_params.is_inc_sn)
// 			memcpy(_sf_params.encryption.vector.sn, meta.region.sf_config.sn, ARMOR_SN_SIZE);

// 		if (_sf_params.encryption.op_mac_params.is_inc_ext_zone)
// 			memcpy(_sf_params.encryption.vector.ex_zone_4b, meta.region.sf_config.extra_zone, 4);
// 	}
// }

// void SecureFlashLib::_set_vector()
// {

// 	uint8_t mac_status = 0;

// 	_sf_params.encryption.vector_len_tot = ARMOR_VECTOR1_SIZE;
// 	_sf_params.encryption.is_imac_from_host = meta.is_imac_en;

// 	memset(_sf_params.encryption.vector.buf, 0, sizeof(_sf_params.encryption.vector.buf));

// 	mac_status = (_sf_params.encryption.is_imac_from_host ? 2 : 0) | (_sf_params.encryption.is_nonce_from_host ? 0 : 1);

// 	/* Configure Vector1 */
// 	_sf_params.encryption.vector.vector_len = ARMOR_VECTOR1_SIZE - 2;
// 	_sf_params.encryption.vector.mfr_id = MFR_ID_MACRONIX;
// 	_sf_params.encryption.vector.armor_cmd = _sf_transport.secure_packet.write.inst;
// 	_sf_params.encryption.vector.op = _sf_transport.secure_packet.write.op;
// 	memcpy(_sf_params.encryption.vector.var1, _sf_transport.secure_packet.write.var1, ARMOR_VAR1_SIZE);
// 	memcpy(_sf_params.encryption.vector.var2, _sf_transport.secure_packet.write.var2, ARMOR_VAR2_SIZE);
// 	_sf_params.encryption.vector.mac_status = mac_status;
// 	if (ARMOR_INST_MC == _sf_transport.secure_packet.write.inst)
// 		memcpy(_sf_params.encryption.vector.reserved_mc,
// 				meta.region.mc[_sf_transport.secure_packet.write.var1[1]], ARMOR_MC_SIZE);

// 	/* Configure Vector2 */
// 	if (_sf_params.encryption.op_mac_params.inc_mac_params) {

// 		_sf_params.encryption.vector.vector_len += ARMOR_VECTOR2_SIZE;
// 		_sf_params.encryption.vector_len_tot += ARMOR_VECTOR2_SIZE;

// 		if (_sf_params.encryption.op_mac_params.is_inc_linked_mc)
// 			memcpy(_sf_params.encryption.vector.linked_mc,
// 					meta.region.mc[_sf_params.encryption.linked_mc_id], ARMOR_MC_SIZE);

// 		if (_sf_params.encryption.op_mac_params.is_inc_sn)
// 			memcpy(_sf_params.encryption.vector.sn, meta.region.sf_config.sn, ARMOR_SN_SIZE);

// 		if (_sf_params.encryption.op_mac_params.is_inc_ext_zone)
// 			memcpy(_sf_params.encryption.vector.ex_zone_4b, meta.region.sf_config.extra_zone, 4);
// 	}
// }

void SecureFlashLib::_generate_random_number(uint8_t *buf, uint8_t size)
{	
	uint8_t n;

	srand(time(NULL));
	for (n = 0; n < size; n++) {
		buf[n] = (rand() % 256);
	}	
}

// void SecureFlashLib::_get_aes_ccm_params(const uint8_t *buf, AesCcmGcmOperationEnum *operation)
// {
// 	memset(&security_operation_params, 0, sizeof (security_op_params));
// 	security_op_params.ccm_gcm_params.security_operation = operation;

// 	if (NO_SECURITY_OPERATION == security_operation)
// 		return ;

// 	_set_vector();

// 	security_data.ccm_gcm_params.key_len = ARMOR_KEY_SIZE;
// 	memcpy(security_data.ccm_gcm_params.key, meta.region.key[_sf_params.encryption.cbc_key_id], security_data.ccm_gcm_params.key_len);
// 	security_data.ccm_gcm_params.iv_len = ARMOR_NONCE_SIZE + ARMOR_MACOUNT_SIZE;
// 	memcpy(security_data.ccm_gcm_params.iv, _sf_params.encryption.iv.nonce_tot, security_data.ccm_gcm_params.iv_len);
// 	security_data.ccm_gcm_params.add_len = _sf_params.encryption.vector.vector_len;
// 	memcpy(security_data.ccm_gcm_params.add, _sf_params.encryption.vector.buf + 2, security_data.ccm_gcm_params.add_len);
// 	security_data.ccm_gcm_params.tag_len = ARMOR_MAC_SIZE;

// 	switch(security_operation) {
// 		case AUTHEN_MAC_DECRYPT_DATA:
// 			security_data.ccm_gcm_params.data_len = ARMOR_DATA_MAX_SIZE;
// 			memcpy(security_data.ccm_gcm_params.data, buf, security_data.ccm_gcm_params.data_len);
// 			memcpy(security_data.ccm_gcm_params.tag, _sf_params.encryption.mac, security_data.ccm_gcm_params.tag_len);
// 			break;
// 		case AUTHEN_MAC_DECRYPT_KEY:
// 			security_data.ccm_gcm_params.data_len = ARMOR_KEY_SIZE;
// 			memcpy(security_data.ccm_gcm_params.data, buf, security_data.ccm_gcm_params.data_len);
// 			memcpy(security_data.ccm_gcm_params.tag, _sf_params.encryption.mac, security_data.ccm_gcm_params.tag_len);
// 			break;
// 		case AUTHEN_MAC:
// 			memcpy(security_data.ccm_gcm_params.tag, _sf_params.encryption.mac, security_data.ccm_gcm_params.tag_len);
// 			break;
// 		case ENCRYPT_MAC_DATA:
// 			security_data.ccm_gcm_params.data_len = ARMOR_DATA_MAX_SIZE;
// 			/* for ersae */
// 			memcpy(security_data.ccm_gcm_params.data, buf, security_data.ccm_gcm_params.data_len);
// 			break;

// 		case ENCRYPT_MAC_KEY:
// 			security_data.ccm_gcm_params.data_len = ARMOR_KEY_SIZE;
// 			break;
// 	default:
// 		break;;
// 	}
// }

static int flashiap_erase(uint32_t addr, uint32_t size)
{
	int result;

	printf("Initialzie FlashIAP\r\n");    

    uint32_t flash_start = flash.get_flash_start();
    printf("start address: %" PRIu32 "\r\n", flash_start);
	if (MBED_FLASH_INVALID_SIZE == flash_start) {
		return MXST_ERR;
	}    

    uint32_t flash_size = flash.get_flash_size();
    printf("flash size: %" PRIu32 "\r\n", flash_size);
	if (MBED_FLASH_INVALID_SIZE == flash_size) {
		return MXST_ERR;
	}

    uint32_t page_size = flash.get_page_size();
    printf("page size: %" PRIu32 "\r\n", page_size);
	if (MBED_FLASH_INVALID_SIZE == page_size) {
		return MXST_ERR;
	}    

    uint32_t last_sector_size = flash.get_sector_size(flash_start + flash_size - 1);
    printf("last sector size: %" PRIu32 "\r\n", last_sector_size);
	if (MBED_FLASH_INVALID_SIZE == last_sector_size) {
		return MXST_ERR;
	}
    
    printf("Erase flash: %" PRIu32 " %" PRIu32 "\r\n", addr, size);

    result = flash.erase(addr, size);
    if (0 != result) {
		return MXST_ERR;
	}

	return MXST_SUCCESS;
}

static int flashiap_program(uint32_t addr, uint8_t *data, uint32_t size)
{ 	
    uint32_t flash_size = flash.get_flash_size();
    uint32_t page_size = flash.get_page_size();    

    printf("program: %" PRIu32 " %" PRIu32 "\r\n", addr, size);

    uint32_t index = 0;
    while (index < size)
    {
        if ((addr + index + page_size) > (addr + flash_size)) {
		 	return MXST_ERR;
		}

        int result = flash.program(data + index, addr + index, page_size);

        if (result != 0)
        {
            printf("program: %" PRIu32 " %" PRIu32 "\r\n", addr + index, page_size);
			return MXST_ERR;
        }

        index += page_size;
    }

	return MXST_SUCCESS;
}

static int flashiap_read(size_t addr, uint8_t *data, size_t size)
{	
    uint32_t page_size = flash.get_page_size();    

	size_t index = 0;
    while (index < size)
    {
        uint32_t read_length = size - index;

        if (read_length > page_size)
        {
            read_length = page_size;
        }        

        int result = flash.read(data, addr + index, read_length);
        if (0 != result) {
			return MXST_ERR;
		}

        index += read_length;
    }
	return MXST_SUCCESS;
}