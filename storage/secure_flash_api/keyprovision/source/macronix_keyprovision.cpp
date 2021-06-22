#include "macronix_keyprovision.h"

//#include <string.h>
//#include <stdio.h>
//#include <stdlib.h>

// #define SEED_KEY_ID      0
// #define ROOT_KEY_ID      1
// #define SESSION_KEY_ID_1 2
// #define SESSION_KEY_ID_2 3

// typedef struct {
// 	uint8_t *salt;
// 	bd_size_t salt_len;
// 	uint8_t *ikm;
// 	bd_size_t ikm_len;
// 	uint8_t *info;
// 	bd_size_t info_len;
// } hkdf_params_t;

// static int symmetric_key_provision(SecureFlashBlockDevice *sfbd);
// static int asymmetric_key_provision(SecureFlashBlockDevice *sfbd);
// static int check_config(SecureFlashBlockDevice *sfbd, uint8_t *cfg_blob, uint8_t *cfg_mask, securefield_config_memory_t *sf_cfg_mem_now);
// static void get_message_blob(uint8_t *msg, bd_size_t msg_len, bd_size_t *rtn_msg_len);
// static int generate_seed_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len, uint8_t *msg, bd_size_t msg_len);
// static int generate_root_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len, uint8_t *msg, bd_size_t msg_len);
// static int set_seed_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len,
// 		uint8_t *msg, bd_size_t act_msg_len, securefield_config_memory_t *sf_cfg_mem_now);
// static int set_root_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len,
// 		uint8_t *msg, bd_size_t act_msg_len, securefield_config_memory_t *sf_cfg_mem_now);
// static int set_session_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len);


// int secureflash_keyprovision(SecureFlashBlockDevice *sfbd)
// {
//     int status = SECUREFLASH_BD_ERROR_OK;

//     status = sfbd->init();
//     if (status) {
//     	return SECUREFLASH_BD_ERROR_INIT;
//     }

//     switch (sfbd->spf.session_encryption_type) {
//     case SYMMETRIC_ENCRYPTION:
//     	status = symmetric_key_provision(sfbd);
//     	break;
//     case ASYMMETRIC_ENCRYPTION:
//     	status = asymmetric_key_provision(sfbd);
//     	break;
//     default:
//     	status = SECUREFLASH_BD_ERROR_NO_DEFINITION;
//     	break;
//     }

//     return status;
// }

// // for non-volatile memory
// static int symmetric_key_provision(SecureFlashBlockDevice *sfbd)
// {
// 	int status;
// 	uint8_t msg[32] = {}, *key;
// 	bd_size_t msg_len = sizeof(msg), act_msg_len, key_len;
// 	securefield_config_memory_t sf_cfg_mem_now = {};

// 	SET_BLOB_VALID(cfg_blob);
// 	SET_BLOB_MASK(cfg_mask);

// 	MX_DBG("------Bootstrap start------\r\n");

// 	status = sfbd->get_config(sf_cfg_mem_now.buf);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		status = SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		goto exit_point;
// 	}

// 	key = new (std::nothrow) uint8_t[sfbd->spf.sym_enc.secret_key_len];
// 	if (!key) {
// 		status = SECUREFLASH_BD_ERROR_ALLOC;
// 		goto exit_point;
// 	}
// 	key_len = sfbd->spf.sym_enc.secret_key_len;

// 	/* for generating the key */
// 	get_message_blob(msg, msg_len, &act_msg_len);

// 	/* set Key0 as seed key */
// 	status = set_seed_key(sfbd, key, key_len, msg, act_msg_len, &sf_cfg_mem_now);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		goto exit_point;
// 	}

// 	/* check the values of configuration and lock the ConfigLKD register */
// 	status = check_config(sfbd, cfg_blob, cfg_mask, &sf_cfg_mem_now);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		goto exit_point;
// 	}

// 	/* set Key1 as root key */
// 	status = set_root_key(sfbd, key, key_len, msg, act_msg_len, &sf_cfg_mem_now);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		goto exit_point;
// 	}

// 	status = set_session_key(sfbd, key, key_len);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		goto exit_point;
// 	}

// exit_point:
// 	if (key) {
// 		delete[] key;
// 	}
// 	MX_DBG("------Bootstrap end------[%s]\r\n", (SECUREFLASH_BD_ERROR_OK == status) ? "PASS" : "FALIED");
// 	return status;
// }

// static int asymmetric_key_provision(SecureFlashBlockDevice *sfbd)
// {
// 	return 0;
// }

// static int check_config(SecureFlashBlockDevice *sfbd, uint8_t *cfg_blob, uint8_t *cfg_mask, securefield_config_memory_t *sf_cfg_mem_now)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;

// 	securefield_config_memory_t *sf_cfg_mem_blob = {};
// 	securefield_config_memory_t *sf_cfg_mem_mask = {};

// 	/* read secure field configuration */
// 	status = sfbd->get_config(sf_cfg_mem_now->buf);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}

// 	sf_cfg_mem_blob = (securefield_config_memory_t *)cfg_blob;
// 	sf_cfg_mem_mask = (securefield_config_memory_t *)cfg_mask;

// 	if (ARMOR_LKD_REG_NOT_LKD == (sf_cfg_mem_now->lock_reg[TARGET_LKD_CONFIG] & ARMOR_LKD_REG_MASK)) {
// 		MX_DBG("[bootstrap] ConfigLKD register is unlock\r\n");
// 		/* set configurations for data/key/mc before locking*/
// 		status = sfbd->set_config(cfg_blob, cfg_mask);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			MX_ERR("[bootstrap] ConfigLKD Register is unlocked, "
// 					"but write blob data to secure field configuration memory failed, %d\r\n", status);
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}

// 		/* lock-down ConfigReg */
// 		status = sfbd->lock_configlkd_reg();
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			MX_ERR("[bootstrap] ConfigLKD register lock-down failed, %d\r\n", status);
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}

// 		/* read secure field configuration to check the lock status */
// 		status = sfbd->get_config(sf_cfg_mem_now->buf);
// 		if (MXST_SUCCESS != status)
// 			return status;

// 		if ( ARMOR_LKD_REG_NOT_LKD == (sf_cfg_mem_now->lock_reg[TARGET_LKD_CONFIG] & ARMOR_LKD_REG_MASK)) {
// 			MX_ERR("[bootstrap] Lock-donw ConfigLKD register is failed\r\n");
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 		MX_DBG("[bootstrap] Lock-down LKDConfig register successfully\r\n");

// 	} else {
// 		uint8_t not_match = 0, cmp_data;
// 		int n;

// 		MX_DBG("[bootstrap] ConfigLKD register is locked\r\n");
// 		/* Not compared with IndKeyLKD of seed key (key0) and root key (key1). */
// 		sf_cfg_mem_mask->key_config[SEED_KEY_ID][KEY_CFG_BYTE_3] |= ARMOR_LKD_REG_NOT_LKD;
// 		sf_cfg_mem_mask->key_config[ROOT_KEY_ID][KEY_CFG_BYTE_3] |= ARMOR_LKD_REG_NOT_LKD;

// 		for (n = 0; n < SECUREFIELD_CFG_SIZE; n++) {
// 			cmp_data = (sf_cfg_mem_blob->buf[n] ^ sf_cfg_mem_now->buf[n]) & ~sf_cfg_mem_mask->buf[n];
// 			if (0xFF != cfg_mask[n] && cmp_data) {
// 				MX_ERR("[bootstrap] comparison failed: addr: %08X, expect: %02X, mask: %02X, act: %02X\r\n",
// 						SECUREFIELD_CFG_ADDR_S + n, sf_cfg_mem_blob->buf[n], sf_cfg_mem_mask->buf[n], sf_cfg_mem_now->buf[n]);
// 				if (!not_match)
// 					not_match = 1;
// 			}
// 		}
// 		if (not_match) {
// 			MX_ERR("[bootstrap] ConfigLKD Register is locked, however, the comparison with the expected data is inconsistent!\r\n");
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 		MX_DBG("[bootstrap] The configuration of the comparison is consistent\r\n");
// 		return status;
// 	}
// 	return status;
// }

// static void get_message_blob(uint8_t *msg, bd_size_t msg_len, bd_size_t *rtn_msg_len)
// {
// 	uint8_t default_msg[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

// 	MBED_ASSERT(msg);
// 	MBED_ASSERT(rtn_msg_len);

//     /* TODO: The messages can be retrieved via usb, uart, flash, etc. to replace the default values. */
// 	*rtn_msg_len = msg_len > sizeof(default_msg) ? sizeof(default_msg) : msg_len;

// 	memcpy(msg, default_msg, *rtn_msg_len);
// }

// static int generate_seed_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len, uint8_t *msg, bd_size_t msg_len)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;

// 	uint8_t secureflash_uid[ARMOR_SN_SIZE] = {};
// 	bd_size_t secureflash_uid_len = sizeof(secureflash_uid);
// 	uint8_t cpu_uid[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
// 	bd_size_t cpu_uid_len = sizeof(cpu_uid);
// 	hkdf_params_t hkdf_params = {};

// 	MBED_ASSERT(sfbd);
// 	MBED_ASSERT(key);
// 	MBED_ASSERT(msg);

// 	/* set message blob as info of HKDF parameter */
// 	hkdf_params.info = msg;
// 	hkdf_params.info_len = msg_len;

// 	/*
// 	 * set CPU unique ID as salt of HKDF parameter
// 	 * TODO: Implement a flow to obtain a unique CUP ID to replace the default value.
// 	 */
// 	hkdf_params.salt = cpu_uid;
// 	hkdf_params.salt_len = cpu_uid_len;

// 	/* set Secure Flash unique ID as ikm of HKDF parameter */
// 	if (sfbd->spf.sym_enc.uid_len) {
// 		hkdf_params.ikm = new (std::nothrow) uint8_t[sfbd->spf.sym_enc.uid_len];
// 		if (!hkdf_params.ikm)
// 			return SECUREFLASH_BD_ERROR_ALLOC;
// 		status = sfbd->get_secure_flash_uid(hkdf_params.ikm, sfbd->spf.sym_enc.uid_len);
// 		if (status) {
// 			status = SECUREFLASH_BD_ERROR_HKDF;
// 			goto exit_point;
// 		}
// 		hkdf_params.ikm_len = sfbd->spf.sym_enc.uid_len;
// 	} else {
// 		hkdf_params.ikm = secureflash_uid;
// 		hkdf_params.ikm_len = secureflash_uid_len;
// 	}

// 	if (sfbd->gen_key_by_hkdf(hkdf_params.salt, hkdf_params.salt_len,
// 			hkdf_params.ikm, hkdf_params.ikm_len,
// 			hkdf_params.info, hkdf_params.info_len,
// 			key, key_len)) {
// 		 status = SECUREFLASH_BD_ERROR_HKDF;
// 		 goto exit_point;
// 	}
// 	MX_DBG("seed key: ");
// 	for (bd_size_t n = 0; n < key_len; n++)
// 		MX_DBG("%02X", key[n]);
// 	MX_DBG("\r\n");

// exit_point:
// 	if (sfbd->spf.sym_enc.uid_len) {
// 		delete[] hkdf_params.ikm;
// 	}
// 	return status;
// }

// static int generate_root_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len, uint8_t *msg, bd_size_t msg_len)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	uint8_t puf_code[ARMOR_PUF_SIZE] = {};
// 	bd_size_t puf_code_len = sizeof(puf_code);
// 	uint8_t board_uid[] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa};
// 	bd_size_t board_uid_len = sizeof(board_uid);
// 	hkdf_params_t hkdf_params = {};

// 	MBED_ASSERT(sfbd);
// 	MBED_ASSERT(key);
// 	MBED_ASSERT(msg);

// 	/* set message blob as info of HKDF parameter */
// 	hkdf_params.info = msg;
// 	hkdf_params.info_len = msg_len;

// 	/*
// 	 * set board unique ID as salt of HKDF parameter
// 	 * TODO: Implement a flow to obtain a board unique ID to replace the default value.
// 	 */
// 	hkdf_params.salt = board_uid;
// 	hkdf_params.salt_len = board_uid_len;

// 	/* set Secure Flash PUF code as ikm of HKDF parameter */
// 	if (sfbd->spf.sym_enc.puf_len) {
// 		hkdf_params.ikm = new (std::nothrow) uint8_t[sfbd->spf.sym_enc.puf_len];
// 		if (!hkdf_params.ikm)
// 			return SECUREFLASH_BD_ERROR_ALLOC;
// 		status = sfbd->get_puf(hkdf_params.ikm, sfbd->spf.sym_enc.puf_len);
// 		if (status) {
// 			status = SECUREFLASH_BD_ERROR_BOOSTRAP;
// 			goto exit_point;
// 		}
// 		hkdf_params.ikm_len = sfbd->spf.sym_enc.uid_len;
// 	} else {
// 		hkdf_params.ikm = puf_code;
// 		hkdf_params.ikm_len = puf_code_len;
// 	}

// 	if (sfbd->gen_key_by_hkdf(hkdf_params.salt, hkdf_params.salt_len,
// 			hkdf_params.ikm, hkdf_params.ikm_len,
// 			hkdf_params.info, hkdf_params.info_len,
// 			key, key_len)) {
// 		status = SECUREFLASH_BD_ERROR_HKDF;
// 		goto exit_point;
// 	}

// 	MX_DBG("root key: ");
// 	for (bd_size_t n = 0; n < key_len; n++)
// 		MX_DBG("%02X", key[n]);
// 	MX_DBG("\r\n");

// exit_point:
// 	if (sfbd->spf.sym_enc.puf_len) {
// 		delete[] hkdf_params.ikm;
// 	}
// 	return status;
// }

// static int set_seed_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len,
// 		uint8_t *msg, bd_size_t act_msg_len, securefield_config_memory_t *sf_cfg_mem_now)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	uint8_t is_keylkd_reg_unlock = (ARMOR_LKD_REG_NOT_LKD ==
// 			(sf_cfg_mem_now->lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK));
// 	uint8_t is_seed_key_unlock = ARMOR_LKD_REG_NOT_LKD ==
// 			((sf_cfg_mem_now->key_config[SEED_KEY_ID][KEY_CFG_BYTE_3] & KEY_CFG_IND_LKD_MASK) >> KEY_CFG_IND_LKD_OFS);

// 	/* generate a seed key by HKDF */
// 	status = generate_seed_key(sfbd, key, key_len, msg, act_msg_len);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return status;
// 	}

// 	if (is_keylkd_reg_unlock && is_seed_key_unlock) {
// 		MX_DBG("KeyLKD register and key%d are unlock, try to overwrite the key valued\r\n", SEED_KEY_ID);
// 		status = sfbd->set_sym_key(key, SEED_KEY_ID, SF_SET_KEY_SPI_WR);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 	}

// 	/* send seed key to host */
// 	status = sfbd->set_sym_key(key, SEED_KEY_ID, SF_SYNC_KEY);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}

// 	if (is_keylkd_reg_unlock) {
// 		MX_DBG("KeyLKD register is unlock, try to lock-down\r\n");
// 		status = sfbd->lock_keylkd_reg();
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 	}

// 	if (is_seed_key_unlock) {
// 		MX_DBG("seed key (key%d) is unlock, try to lock-down\r\n", SEED_KEY_ID);
// 		status = sfbd->lock_ind_key(SEED_KEY_ID);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 	}

// 	/* read secure field configuration to check the lock status */
// 	status = sfbd->get_config(sf_cfg_mem_now->buf);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	is_keylkd_reg_unlock = (ARMOR_LKD_REG_NOT_LKD ==
// 				(sf_cfg_mem_now->lock_reg[TARGET_LKD_KEY] & ARMOR_LKD_REG_MASK));

// 	is_seed_key_unlock = ARMOR_LKD_REG_NOT_LKD ==
// 			((sf_cfg_mem_now->key_config[SEED_KEY_ID][KEY_CFG_BYTE_3] & KEY_CFG_IND_LKD_MASK) >> KEY_CFG_IND_LKD_OFS);

// 	if (is_keylkd_reg_unlock) {
// 		MX_ERR("[bootstrap] Lock-donw KeyLKD register is failed\r\n");
// 		return MXST_ARMOR_LKD_FAILED;
// 	}
// 	MX_DBG("[bootstrap] KeyLKD register is locked\r\n");

// 	if (is_seed_key_unlock) {
// 		MX_ERR("[bootstrap] lock-down seed key (key%d) is failed\r\n", SEED_KEY_ID);
// 		return MXST_ARMOR_LKD_FAILED;
// 	}
// 	MX_DBG("[bootstrap] seed key (key%d) is locked\r\n", SEED_KEY_ID);

// 	return status;
// }

// static int set_root_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len,
// 		uint8_t *msg, bd_size_t act_msg_len, securefield_config_memory_t *sf_cfg_mem_now)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	uint8_t is_root_key_unlock = ARMOR_LKD_REG_NOT_LKD ==
// 			((sf_cfg_mem_now->key_config[ROOT_KEY_ID][KEY_CFG_BYTE_3] & KEY_CFG_IND_LKD_MASK) >> KEY_CFG_IND_LKD_OFS);

// 	/* generate a root key by HKDF */
// 	status = generate_root_key(sfbd, key, key_len, msg, act_msg_len);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}

// 	if (is_root_key_unlock) {
// 		MX_DBG("root key (key%d) is unlock, try to overwrite the key value\r\n", ROOT_KEY_ID);
// 		status = sfbd->set_sym_key(key, ROOT_KEY_ID, SF_SET_KEY_SPI_WR);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 		MX_DBG("root key (key%d) is unlock, try to lock-down\r\n", ROOT_KEY_ID);
// 		status = sfbd->lock_ind_key(ROOT_KEY_ID);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 		}
// 	}

// 	/* send root key to host */
// 	status = sfbd->set_sym_key(key, ROOT_KEY_ID, SF_SYNC_KEY);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}

// 	/* read secure field configuration to check the lock status */
// 	status = sfbd->get_config(sf_cfg_mem_now->buf);
// 	if (MXST_SUCCESS != status)
// 		return status;

// 	is_root_key_unlock = ARMOR_LKD_REG_NOT_LKD ==
// 			((sf_cfg_mem_now->key_config[ROOT_KEY_ID][KEY_CFG_BYTE_3] & KEY_CFG_IND_LKD_MASK) >> KEY_CFG_IND_LKD_OFS);

// 	if (is_root_key_unlock) {
// 		MX_ERR("[bootstrap] lock-down root key (key%d) is failed\r\n", ROOT_KEY_ID);
// 		return MXST_ARMOR_LKD_FAILED;
// 	}
// 	MX_DBG("[bootstrap] root key (key%d) is locked\r\n", ROOT_KEY_ID);
// 	return status;
// }
// static int set_session_key(SecureFlashBlockDevice *sfbd, uint8_t *key, bd_size_t key_len)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	/* set Key2 as session key 1*/
// 	status = sfbd->set_sym_key(key, SESSION_KEY_ID_1, SF_SET_KEY_KGEN);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}
// 	/* send session key1 to host */
// 	status = sfbd->set_sym_key(key, SESSION_KEY_ID_1, SF_SYNC_KEY);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}

// 	/* set Key3 as session key 2*/
// 	status = sfbd->set_sym_key(key, SESSION_KEY_ID_2, SF_SET_KEY_KGEN);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}
// 	/* send session key2 to host */
// 	status = sfbd->set_sym_key(key, SESSION_KEY_ID_2, SF_SYNC_KEY);
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return SECUREFLASH_BD_ERROR_BOOSTRAP;
// 	}
// 	return status;
// }

