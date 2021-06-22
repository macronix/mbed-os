#include "SecureFlashBlockDevice.h"
#include <string.h>
#include <stdio.h>
#include "platform/mbed_assert.h"
#include "mbedtls/ccm.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include <Thread.h>

#ifndef MBED_CONF_MBED_TRACE_ENABLE
#define MBED_CONF_MBED_TRACE_ENABLE        1
#endif

#include "mbed_trace.h"
#define TRACE_GROUP "SECUREFLASH"

#if defined(DEVICE_SPI)
	#define PIN_INIT _flash(io0, io1, clk, cs, mbed::use_gpio_ssel)
#elif defined(DEVICE_QSPI)
	#define PIN_INIT _flash(io0, io1, clk, cs, clock_mode)
#elif defined(DEVICE_OSPI)
	#define PIN_INIT _flash(io0, io1, io2, io3, io4, io5, io6, io7, clk, cs, dqs, clock_mode)
#endif

#define MFR_ID_MACRONIX 0xC2

typedef struct {
	uint8_t *salt;
	bd_size_t salt_len;
	uint8_t *ikm;
	bd_size_t ikm_len;
	uint8_t *info;
	bd_size_t info_len;
	uint8_t *okm;
	bd_size_t okm_len;
} hkdf_params_t;

SingletonPtr<PlatformMutex> SecureFlashBlockDevice::_mutex;

SecureFlashBlockDevice::SecureFlashBlockDevice(
	PinName io0, PinName io1, PinName io2, PinName io3, PinName io4, PinName io5, PinName io6, PinName io7,
	PinName clk, PinName cs, PinName dqs, int clock_mode, int freq)
    : PIN_INIT, _sf_lib(&_flash, freq)
{
}

int SecureFlashBlockDevice::init()
{
	int status = SECUREFLASH_BD_ERROR_OK;

	_mutex->lock();

	if (!_is_initialized) {
		_init_ref_count = 0;
	}

	_init_ref_count++;

	if (_init_ref_count != 1) {
		goto exit_point;
	}

	if (_sf_lib.init()) {
		status = SECUREFLASH_BD_ERROR_INIT;
		goto exit_point;
	}
#ifdef DATAZONE_ISOLATION_MODULE
	status = _check_provision_data();
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}
#endif
    _is_initialized = true;

exit_point:
    _mutex->unlock();

	return status;
}

int SecureFlashBlockDevice::deinit()
{
    int status = SECUREFLASH_BD_ERROR_OK;

    _mutex->lock();

    if (!_is_initialized) {
        _init_ref_count = 0;
        goto exit_point;
    }

    _init_ref_count--;

    if (_init_ref_count) {
        goto exit_point;
    }	

    if (_sf_lib.deinit()) {
    	status = SECUREFLASH_BD_ERROR_DEINIT;
    }

    _is_initialized = false;

exit_point:
    _mutex->unlock();

    return status;
}
#define SESSION_NUM_MAX 4
#define SESSION_LIFETIME_MAX 5

typedef struct {
	osThreadId_t thread_id;
	uint64_t session_id;
	uint64_t app_id;
	uint32_t session_lifetime;	
	uint8_t is_attested:1;
} attested_grp_t;

attested_grp_t attested_grp[SESSION_NUM_MAX];

int SecureFlashBLockDevice::open_session(uint64_t session_id, uint64_t app_id)
{
	int n;
	
	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].session_id == session_id && attested_grp[n].is_attested) {
			attested_grp[n].thread_id = Thread::get_id();	
			return SECUREFLASH_BD_ERROR_OK;
		}
	}
	
	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (!attested_grp[n].is_attested) {
			memset(&attested_grp[n], 0, sizeof(attested_grp[n]));
			attested_grp[n].app_id = app_id;
			attested_grp[n].thread_id = Thread::get_id();			
			return SECUREFLASH_BD_ERROR_NEED_ATTESTATION;
		}
	}

	return SECUREFLASH_BD_ERROR_SESSION_EXHAUST;
}

int SecureFlashBlockDevice::close_session(uint64_t session_id)
{
	int n;
	
	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].session_id == session_id && attested_grp[n].is_attested) {
			break;
		}
	}
	if (SESSION_NUM_MAX == n) {		
		return SECUREFLASH_BD_ERROR_SESSION_ID_NOT_EXIST;
	}

	if (attested_grp[n].thread_id == Thread::get_id()) {
		attested_grp[n].thread_id = NULL;
	} else {		
		return SECUREFLASH_BD_ERROR_THREAD_ID_NOT_EXIST;
	}

	attested_grp[n].session_lifetime++;
	if (SESSION_LIFETIME_MAX <= attested_grp[n].session_lifetime) {
		memset(&attested_grp[n], 0, sizeof(attested_grp[n]);
	}	
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::get_session_id(uint8_t *session_id)
{
	osThreadId_t thread_id = Thread::get_id();

	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].thread_id == thread_id) {
			break;
		}
	}

	if (SESSION_NUM_MAX == n) {
		return SECUREFLASH_BD_ERROR_THREAD_ID_NOT_EXIST;
	}

	if (!attested_grp[n].is_attested) {
		return SECUREFLASH_BD_ERROR_ATTESTATION_NOT_READY;
	}

	if (0 != _sf_lib.get_trng(attestation[n].session_id, sizeof(attested_grp[n].session_id))) {
		return SECUREFLASH_BD_ERROR_GET_SSESSION_ID;
	}

	memcpy(session_id, attested_grp[n].session_id, sizeof(attested_grp[n].session_id));
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::attestation_get_challenge(uint8_t *challenge)
{
	osThreadId_t thread_id = Thread::get_id();

	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].thread_id == thread_id) {
			break;
		}
	}

	if (SESSION_NUM_MAX == n) {
		return SECUREFLASH_BD_ERROR_THREAD_ID_NOT_EXIST;
	}

	if (0 != _sf_lib.get_challenge(attested_grp[n].app_id, challenge)) {
		return SECUREFLASH_BD_ERROR_ATTESTATION_CHALLENGE;
	}	
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::attestation_check_response(uint8_t *response)
{
	osThreadId_t thread_id = Thread::get_id();

	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].thread_id == thread_id) {
			break;
		}
	}

	if (SESSION_NUM_MAX == n) {
		return SECUREFLASH_BD_ERROR_THREAD_ID_NOT_EXIST;
	}	
	
	switch (_sf_lib.secure_flash_profile.cipher_suite.signature) {
	case ENC_ECDSA_SECP256R1:
	{
		uint8_t *message, *pub_key, *sig;
		uint8_t message_len;

		if (0 != _sf_lib.get_ecdsa_256r1_params(response, message, &message_len, pub_key, sig)) {
			return SECUREFLASH_BD_ERROR_ATTESTATION_RESPONSE;
		}
		status = _ecdsa_secp256r1_verify(message, messae_len, pub_key, sig);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			return status;
		}
		break;
	}
	default:
		return SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP;
	}

	attested_grp[n].is_attested = 1;

	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::_check_provision_data(void *provision_data))
{
	int status = SECUREFLASH_BD_ERROR_OK;
	encryption_indicator_t verify_indicator = {};
	
	status = _sf_lib.parse_provision_data(provision_data, &verify_indicator);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_CHECK_PROVISION;
	}

	status = _encryption_exec(&verify_indicator);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_CHECK_PROVISION;
	}
	return status;
}

int SecureFlashBlockDevice::write_provision(void *provision_data)
{
	int status = SECUREFLASH_BD_ERROR_OK;	
	
	status = _check_provision_data(provision_data);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}

	status = _sf_lib.write_provision_data(provision_data);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_WRITE_PROVISION;
	}
	return status;
}

int SecureFlashBlockDevice::read_provision(uint8_t *provision_data, uint64_t size)
{
	int status = SECUREFLASH_BD_ERROR_OK;

	status = _sf_lib.read_provision_data(provision_data, size);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_READ_PROVISION;
	}
	return status;
}

int SecureFlashBlockDevice::lock_provision(void *provision_data)
{
	int status = SECUREFLASH_BD_ERROR_OK;

	status = _sf_lib.lock_provision_data(provision_data);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_LOCK_PROVISION;
	}
	return status;
}

int SecureFLashBLockDevice::_check_permission()
{
	osThreadId_t thread_id = Thread::get_id();
	int n;

	for (n = 0; n < SESSION_NUM_MAX; n++) {
		if (attested_grp[n].thread == thread_id) {
			break;
		}
	}
	if (SESSION_NUM_MAX == n) {		
		return SECUREFLASH_BD_ERROR_NO_SECURITY_PERMISION;
	}

	if (!attested_grp[n].is_attested) {
		return SECUREFLASH_BD_ERROR_NO_SECURITY_PERMISION;
	}

	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::read(void *buffer, bd_addr_t addr, bd_size_t buffer_size)
{
	int status = SECUREFLASH_BD_ERROR_OK;
	
	const bd_size_t read_size = get_read_size();
	bd_size_t ofs, remain;
	uint8_t *read_buf, *buf = (uint8_t *)buffer;
	int n;	

	MX_DBG("Read addr: %" PRIx64 ", size: %" PRIx64 "\r\n", addr, buffer_size);	

    if (!_is_initialized) {
        return BD_ERROR_DEVICE_ERROR;
    }

	if ((addr + buffer_size) > size())
		return SECUREFLASH_BD_ERROR_ACCESS_ADDR_EXCEEDED;

	_mutex->lock();

	status = _check_permission();
	if (SECUREFLASH_BD_ERROR_OK != status) {
		_sf_lib.stardard_spi_read(buffer, size)
	}

	read_buf = new (std::nothrow) uint8_t[read_size];
	MBED_ASSERT(read_buf);

	ofs = addr % read_size;
	if (ofs) {
		status = _read_operation(read_buf, addr - ofs, read_size);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			goto exit_point;
		}

		remain = read_size - ofs;

		if (remain > buffer_size) {
			memcpy(buf, read_buf + ofs, buffer_size);
			status = SECUREFLASH_BD_ERROR_OK;
			goto exit_point;
		} else {
			memcpy(buf, read_buf + ofs, remain);
		}
		buf += remain;
		addr += remain;
		buffer_size -= remain;
	}

	remain = (addr + buffer_size) % read_size;
	if (remain)
		buffer_size -= remain;

	while (buffer_size) {
		status = _read_operation(buf, addr, read_size);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			goto exit_point;
		}
		buf += read_size;
		addr += read_size;
		buffer_size -= read_size;
	}

	if (remain) {
		status = _read_operation(read_buf, addr, read_size);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			goto exit_point;
		}
		memcpy(buf, read_buf, remain);
	}
exit_point:
    delete[] read_buf;
	_mutex->unlock();
	return status;
}

int SecureFlashBlockDevice::program(const void *buffer, bd_addr_t addr, bd_size_t buffer_size)
{
	int status = SECUREFLASH_BD_ERROR_OK;
	const bd_size_t pgm_size = get_program_size();
	bd_size_t ofs, remain;
	uint8_t *pgm_buf, *buf = (uint8_t *)buffer;

	MX_DBG("Program addr: %" PRIx64 ", size: %" PRIx64 "\r\n", addr, buffer_size);

    if (!_is_initialized) {
        return BD_ERROR_DEVICE_ERROR;
    }

    if ((addr + buffer_size) > size()) {
    	return SECUREFLASH_BD_ERROR_ACCESS_ADDR_EXCEEDED;
    }

    _mutex->lock();

    pgm_buf = new (std::nothrow) uint8_t[pgm_size];
    MBED_ASSERT(pgm_buf);

    ofs = addr % pgm_size;
    if (ofs) {
    	memset(pgm_buf, 0xFF, pgm_size);
    	remain = pgm_size - ofs;
    	remain = remain > buffer_size ? buffer_size : remain;
    	memcpy(pgm_buf + ofs, buf, remain);

    	status = _program_operation(pgm_buf, addr - ofs, pgm_size);
    	if (SECUREFLASH_BD_ERROR_OK != status) {
    		goto exit_point;
    	}

    	if (remain == buffer_size) {
    		status = SECUREFLASH_BD_ERROR_OK;
    		goto exit_point;
    	}

    	buf += remain;
    	addr += remain;
    	buffer_size -= remain;
    }

    remain = (addr + buffer_size) % pgm_size;
    if (remain)
    	buffer_size -= remain;

    while(buffer_size) {
    	status = _program_operation(buf, addr, pgm_size);
    	if (SECUREFLASH_BD_ERROR_OK != status) {
    		goto exit_point;
    	}

    	buf += pgm_size;
    	addr += pgm_size;
    	buffer_size -= pgm_size;
    }

    if (remain) {
    	memset(pgm_buf, 0xff, pgm_size);
    	memcpy(pgm_buf, buf, remain);
    	status = _program_operation(pgm_buf, addr, pgm_size);
    	if (SECUREFLASH_BD_ERROR_OK != status) {
			goto exit_point;
		}
    }
exit_point:
	delete[] pgm_buf;
	_mutex->unlock();
	return status;
}

int SecureFlashBlockDevice::erase(bd_addr_t addr, bd_size_t ers_size)
{
	int status = SECUREFLASH_BD_ERROR_OK;
	const bd_size_t min_ers_size = get_erase_size();

	MX_DBG("Erase addr: %" PRIx64 ", size: %" PRIx64 ", min erase size: %" PRIx64 "\r\n", addr, ers_size, min_ers_size);

    if (!_is_initialized) {
        return BD_ERROR_DEVICE_ERROR;
    }

	if ((addr + ers_size) > size())
		return MXST_ARMOR_ACCESS_ADDR_EXCEEDED_ERR;

	if ((addr % min_ers_size || (addr + ers_size) % min_ers_size)) {
		MX_ERR("Erase size is not aligned to %" PRIx64 "-bytes\r\n", min_ers_size);
		return MXST_ARMOR_ERASE_NOT_ALIGN_4K;
	}

	_mutex->lock();

	while (ers_size >= min_ers_size) {
		status = _erase_operation(addr);
		if (MXST_SUCCESS != status) {
			goto exit_point;
		}
		addr += min_ers_size;
		ers_size -= min_ers_size;
	}
exit_point:
	_mutex->unlock();
	return status;
}

int SecureFlashBlockDevice::_read_operation(uint8_t *buffer, bd_addr_t addr, bd_size_t buffer_size)
{
	command_params_t cmd_params = {};	

	cmd_params.name = CMDNAME_READ;
	cmd_params.address = addr;
	cmd_params.odata = buffer;
	cmd_params.odata_len = buffer_size;
	
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);
}

int SecureFlashBlockDevice::_program_operation(uint8_t *buffer, bd_addr_t addr, bd_size_t buffer_size)
{	
	command_params_t cmd_params = {};	

	cmd_params.name = CMDNAME_PROGRAM;
	cmd_params.address = addr;
	cmd_params.idata = buffer;
	cmd_params.idata_len = buffer_size;
	
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);
}

int SecureFlashBlockDevice::_erase_operation(bd_addr_t addr)
{	
	command_params_t cmd_params = {};	

	cmd_params.name = CMDNAME_ERASE;
	cmd_params.address = addr;	
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);	
}

int SecureFlashBlockDevice::get_uid(uint8_t *uid, bd_size_t size)
{
	command_params_t cmd_params = {};
	
	cmd_params.name = CMDNAME_RD_UID;
	cmd_params.odata = uid;
	cmd_params.odata_len = size;
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);	
}

int SecureFlashBlockDevice::get_puf(uint8_t *puf, bd_size_t size)
{	
	command_params_t cmd_params = {};
	
	cmd_params.name = CMDNAME_RD_PUF;
	cmd_params.odata = puf;
	cmd_params.odata_len = size;
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);	
}
int SecureFlashBlockDevice::get_trng(uint8_t *trng, bd_size_t size)
{	
	command_params_t cmd_params = {};
	
	cmd_params.name = CMDNAME_RD_TRNG;
	cmd_params.odata = trng;
	cmd_params.odata_len = size;
	// TODO: app_id should be update with thread id
	cmd_params.app_id = 0;

	return _security_operation(&cmd_params);
}

int SecureFlashBlockDevice::_security_operation(command_params_t *cmd_params)
{
	int status = SECUREFLASH_BD_ERROR_OK;	
	command_requirement_t *cmd_req = 
		&_sf_lib.secure_flash_profile.command_requirement.index[cmd_params->name];
	
	status = _check_write_secure_packet(cmd_params, cmd_req);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}	

	status = _write_secure_packet(cmd_params);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}	

	status = _read_secure_packet(cmd_params);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}
	
	return _check_read_secure_packet(cmd_params, cmd_req);	
}

int SecureFlashBlockDevice::_write_secure_packet(command_params_t *cmd_params, encryption_indicator_t *enc_indicator)
{
	if (0 != _sf_lib.write_secure_packet(cmd_params, enc_indicator)) {
		return SECUREFLASH_BD_ERROR_WR_RD_SECURE_PKT;
	}
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::_read_secure_packet(command_params_t *cmd_params, encryption_indicator_t *enc_indicator)
{
	if (0 != _sf_lib.read_secure_packet(cmd_params, enc_indicator)) {
		return SECUREFLASH_BD_ERROR_WR_RD_SECURE_PKT;
	}
	return SECUREFLASH_BD_ERROR_OK;
}
int SecureFlashBlockDevice::_check_write_secure_packet(command_params_t *cmd_params, command_requirement_t *cmd_req, 
		encryption_indicator_t *write_indicator)
{
	if (OP_NO_SECURITY_OPERATION == cmd_req->write_packet_op) {
		return SECUREFLASH_BD_ERROR_OK;
	}	

	return _check_encryption(cmd_params, cmd_req->write_packet_alg, cmd_req->write_packet_op);
}

int SecureFlashBlockDevice::_check_read_secure_packet(command_params_t *cmd_params, command_requirement_t *cmd_req, 
		encryption_indicator_t *read_indicator)
{	
	int status = SECUREFLASH_BD_ERROR_OK;

	if (OP_NO_SECURITY_OPERATION == cmd_req->read_packet_op) {
		return SECUREFLASH_BD_ERROR_OK;
	}	

	return _check_encryption(cmd_params, cmd_req->read_packet_alg, cmd_req->read_packet_op);	
}

int SecureFlashBlockDevice::_check_encryption(command_params_t *cmd_params, 
		EncryptionAlgorithm packet_alg, EncryptionOperationEnum packet_op)
{
	int status = MXST_SUCCESS;
	encryption_indicator_t encryption_indicator = {};

	encryption_indicator.encryption = packet_alg;
	encryption_indicator.operation = packet_op;

	switch (packet_alg) {
	case ALG_HMAC_SHA_1:
	case ALG_HMAC_SHA_256:
	case ALG_HMAC_SHA_384:
	case ALG_HMAC_SHA_512:
		break;
	case ALG_AES_CCM_128:
	case ALG_AES_CCM_192:
	case ALG_AES_CCM_256:		
		status = _get_ccm_params(&encryption_indicator, cmd_params);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			return status;			
		}

		status = _encryption_exec(&encryption_indicator);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			return status;
		}		
		break;
	case ALG_AES_GCM_128:
	case ALG_AES_GCM_192:
	case ALG_AES_GCM_256:
		break;
	case ALG_AES_ECB_128:
	case ALG_AES_ECB_192:
	case ALG_AES_ECB_256:
		break;
	case ALG _AES_CBC_128:
	case ALG_AES_CBC_192:
	case ALG_AES_CBC_256:
		break;
	case ALG_AES_OFB_128:
	case ALG_AES_OFB_192:
	case ALG_AES_OFB_256:
		break;
	case ALG_AES_CTR_128:
	case ALG_AES_CTR_192:
	case ALG_AES_CTR_256:
		break;
	default:
		return SECUREFALSH_BD_ERROR_ENCRYPTION_NOT_SUP;
	}
	return status;
}

int SecureFlashBlockDevice::_get_ccm_params(encryption_indicator_t *indicator, command_params_t *cmd_params)
{
	int status = MXST_SUCCESS;

	status = _sf_lib.get_ccm_params(indicator, cmd_params);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return SECUREFLASH_BD_ERROR_AUTHEN;
	}

	/* check if iv needs encryption */
	switch (indicator->operation) {
	case ENCOP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV:
	case ENCOP_AUTHEN_TAG_ENC_IV:
	case ENCOP_DECRYPT_DATA_ENC_IV:
	case ENCOP_ENCRYPT_TAG_DATA_ENC_IV:
	case ENCOP_ENCRYPT_TAG_ENC_IV:
	case ENCOP_ENCRYPT_DATA_ENC_IV:
		/* check if iv needs encryption */
		_encryption_exec(indicator->aes_ccm_gcm.iv_enc);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			return SECUREFLASH_BD_ERROR_AUTHEN;
		}
		status = _sf_lib.get_iv(indicator);
		if (SECUREFLASH_BD_ERROR_OK != status) {
			return SECUREFLASH_BD_ERROR_AUTHEN;
		}
		break;
	default:
		break;
	}

	return status;
}

int SecureFlashBlockDevice::_encryption_exec(encryption_indicator_t *indicator)
{
	int status = SECUREFLASH_BD_ERROR_OK;

	switch (indicator->encryption) {
	case ENC_NONE:
		return MXST_SUCCESS;
	case ENC_AES_CCM_128:
	case ENC_AES_CCM_192:
	case ENC_AES_CCM_256:
		status = _aes_ccm_exec(indicator);
		break;
	case ENC_AES_ECB_128:
	case ENC_AES_ECB_192:
	case ENC_AES_ECB_256:
		status = _aes_ecb_exec(indicator);
		break;	
	case ENC_ECDSA_SECP192R1:
    case ENC_ECDSA_SECP224R1:
    case ENC_ECDSA_SECP256R1:
    case ENC_ECDSA_SECP384R1:
    case ENC_ECDSA_SECP521R1:
    case ENC_ECDSA_BP256R1:  
    case ENC_ECDSA_BP384R1:  
    case ENC_ECDSA_BP512R1:  
    case ENC_ECDSA_CURVE25519:
    case ENC_ECDSA_SECP192K1:
    case ENC_ECDSA_SECP224K1:
    case ENC_ECDSA_SECP256K1:
    case ENC_ECDSA_CURVE448: 
		status = _aes_ecdsa_exec(indicator);
		break;
	case ENC_HMAC_SHA256:
		status = _hmac_exec(indiator);
		break;
	default:
		/* TODO: implementation of related encryption if needed */
		break;
	}
	return status;
}

int SecureFlashBlockDevice::_aes_ccm_exec(encryption_indicator_t *indicator)
{
	int status = SECUREFLASH_BD_ERROR_OK;
	static mbedtls_ccm_context ccm_ctx = {};

	mbedtls_ccm_free(&ccm_ctx);
	mbedtls_ccm_init(&ccm_ctx);

	status = mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, indicator->aes_ccm_gcm.key, indicator->aes_ccm_gcm.key_len * 8);
	if (0 != status) {
		MX_ERR("AES CCM setkey error : %d\r\n", status);
		return SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
	}
	switch (indicator->operation) {		
	case ENCOP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV:
	case ENCOP_AUTHEN_TAG_DECRYPT_DATA:
	case ENCOP_AUTHEN_TAG_ENC_IV:
	case ENCOP_AUTHEN_TAG:		

		status = mbedtls_ccm_auth_decrypt(&ccm_ctx, indicator->aes_ccm_gcm.data_len,
					indicator->aes_ccm_gcm.iv, indicator->aes_ccm_gcm.iv_len,
					indicator->aes_ccm_gcm.add, indicator->aes_ccm_gcm.add_len,
					indicator->aes_ccm_gcm.idata, indicator->aes_ccm_gcm.odata,
					indicator->aes_ccm_gcm.tag, indicator->aes_ccm_gcm.tag_len);
		if (0 != status) {
			MX_ERR("MBEDTLS AES CCM error status: %d\r\n", status);
			return SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
		}
		break;
	case ENCOP_ENCRYPT_TAG_DATA_ENC_IV:
	case ENCOP_ENCRYPT_TAG_DATA:
	case ENCOP_ENCRYPT_TAG_ENC_IV:
	case ENCOP_ENCRYPT_TAG:		
		status = mbedtls_ccm_encrypt_and_tag(&ccm_ctx, indicator->aes_ccm_gcm.data_len,
					indicator->aes_ccm_gcm.iv, indicator->aes_ccm_gcm.iv_len,
					indicator->aes_ccm_gcm.add, indicator->aes_ccm_gcm.add_len,
					indicator->aes_ccm_gcm.idata, indicator->aes_ccm_gcm.odata,
					indicator->aes_ccm_gcm.tag, indicator->aes_ccm_gcm.tag_len);
		if (0 != status) {
			MX_ERR("MBEDTLE AES CCM error status: %d\r\n", status);
			return SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
		}
		break;
	default:
		MX_ERR("MBEDTLE AES CCM operation error\r\n");
		return SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;		
	}
	return status;
}

int SecureFlashBlockDevice::_aes_ecb_exec(encryption_indicator_t *indicator)
{
	int status = SECUREFLASH_BD_ERROR_OK, ecb_mode;
	mbedtls_aes_context ctx = {};	

	mbedtls_aes_init(&ctx);

	switch (indicator->operation) {
	case ENCOP_ENCRYPT_DATA:
		status = mbedtls_aes_setkey_dec(&ctx, indicator->aes_ecb.key, indicator->aes_ecb.key_len * 8);
		if(status) {
			MX_ERR("MBEDTLE AES ECB error status: %d\n", status);
			status = SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
			goto exit_point;
		}
		ecb_mode = MBEDTLS_AES_DECRYPT;
		break;
	case ENCOP_DECRYPT_DATA:
		status = mbedtls_aes_setkey_enc(&ctx, indicator->aes_ecb.key, indicator->aes_ecb.key_len * 8);
		if(status) {
			MX_ERR("MBEDTLE AES ECB error status: %d\n", status);
			status = SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
			goto exit_point;
		}
		ecb_mode = MBEDTLS_AES_ENCRYPT;		
		break;
	default:
		MX_ERR("MBEDTLE AES ECB error, operation is not supported\r\n");
		status = SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;
		goto exit_point;
	}

	status = mbedtls_aes_crypt_ecb( &ctx, ecb_mode, indicator->aes_ecb.idata, indicator->aes_ecb.odata);
	if(status) {
		MX_ERR("MBEDTLE AES ECB error status: %d\n", status);
		status = SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION;		
	}
exit_point:
	mbedtls_aes_free(&ctx);
	return status;
}

int SecureFlashBlockDevice::_aes_ecdsa_exec(encryption_indicator_t *indicator) 
{
	int status = SECUREFLASH_BD_ERROR_OK;	

	switch (indicator->operation) {	
	case ENCOP_SIGNATURE_VERIFY:
		status = ecdsa_secp256r1_verify(indicator->ecdsa.message, indicator->ecdsa.message_len, 				
				indicator->ecdsa.pub_key, indicator->ecdsa.pub_key_len,		
				indicator->ecdsa.signature, indicator->ecdsa.signature_len);
		if (0 != status) {
			return status;
		}	
	default:
		break;
	}
	return status;	
}

int SecureFlashBlockDevice::_ecdsa_secp256r1_verify(uint8_t *message, size_t messae_len, uint8_t *pub_key, uint8_t *sig)
{	
	mbedtls_ecdsa_context ctx = {};
	uint8_t hash[32];

	mbedtls_ecdsa_init(&ctx);
	printf("load grp\r\n");
	if (0 != mbedtls_ecp_group_load( &ctx.grp, MBEDTLS_ECP_DP_SECP256R1)) { 	
		MX_ERR( "failed ! mbedtls_ecp_group_load\r\n");
 		return SECUREFLASH_BD_ERROR_ECDSA_VERIFY;
 	}
	printf("read binary\r\n");
	if( 0 != mbedtls_ecp_point_read_binary( &ctx.grp, &ctx.Q, pub_key, 65 )) {        
        MX_ERR( "failed ! mbedtls_ecp_point_read_binary\r\n");
        return SECUREFLASH_BD_ERROR_ECDSA_VERIFY;
    }

	printf("sha256\r\n");
	mbedtls_sha256(message, messae_len, hash, 0);
    
	printf("verify\r\n");
	if (0 != mbedtls_ecdsa_read_signature( &ctx, hash, 32, sig, 72)) {	
        MX_ERR( "failed ! ecdsa_read_signature\r\n");
        return SECUREFLASH_BD_ERROR_ECDSA_VERIFY;
    }
	printf("OK\r\n");
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::_hmac_exec(encryption_indicator_t *indicator)
{
	mbedtls_md_type_t md_type;

	switch (indicator->enction) {	        
    case ENC_HMAC_SHA1:
		md_type = MBEDTLS_MD_SHA1;		
		break;
    case ENC_HMAC_SHA224:
		md_type = MBEDTLS_MD_SHA224;
		break;    
    case ENC_HMAC_SHA256:
		md_type = MBEDTLS_MD_SHA256;
		break;
    case ENC_HMAC_SHA384:
		md_type = MBEDTLS_MD_SHA384;
		break;
    case ENC_HMAC_SHA512:
		md_type = MBEDTLS_MD_SHA512;		
		break;
	default:
		break;
	}
	if (0 != mbedtls_md_hmac( mbedtls_md_info_from_type(md_type),
    		indicator->hmac.key, indicator->hmac.key_len,
            indicator->hmac.idata indicator->hmac.data_len, indicator->hmac.odata )) {		
		return SECUREFLASH_BD_ERROR_HMAC;
	}
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::_rpmc_signature_sign(uint8_t key, uint8_t *message, uint8_t message_len, uint8_t *signature)
{
	encryption_indicator_t indicator = {};
	uint8_t idata[PMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE] = {}
	uint8_t signature[RPMC_SIGNATURE_SIZE] = {};
	
	indicator.hmac.idata = message;
	indicator.hmac.data_len = message_len;
	indicator.hmac.key = key;
	indicator.hmac.key_len = RPMC_KEY_SIZE;
	indicator.hmac.odata = signature;
	inidcator.operation = ENCOP_SIGNATURE_SIGN;
	indicator.encryption = ENC_HMAC_SHA_256;

	return _hmac_exec(&indicator);	
}
int SecureFlashBlockDevice::rpmc_write_root_key(uint8_t mc_address, uint8_t *root_key)
{
	int status = SECUREFLASH_BD_ERROR_OK;		
	uint8_t signature[RPMC_SIGNATURE_SIZE] = {};
	uint8_t message[RPMC_INST_SIZE + PMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE];
	uint8_t message_len = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE;

	message[0] = RPMC_INST1;
	message[1] = RPMC_CMD_ROOT_KEY;
	message[2] = mc_address;
	message[3] = RPMC_RESERVED;

	status = _rpmc_signature_sign(root_key, message, message_len, signature);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}
	
	if (0 != _sf_lib.rpmc_write_root_key(RPMC_INST1, RPMC_CMD_ROOT_KEY, counter_address, RPMC_RESERVED, root_key, signature)) {
		return SECUREFLASH_BD_ERROR_RPMC_WRITE_ROOT_KEY;
	}
	return status;
}

int SecureFlashBlockDevice::rpmc_update_hmac_key(uint8_t mc_address, uint8_t *key_data)
{
	int status = SECUREFLASH_BD_ERROR_OK;	
	uint8_t message[RPMC_INST_SIZE + PMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_HMAC_KEY_DATA_SIZE];
	uint8_t message_len = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_HMAC_KEY_DATA_SIZE;
	uint8_t signature[RPMC_SIGNATURE_SIZE] = {};
	uint8_t root_key[RPMC_ROOT_KEY_SIZE] = {};
	uint8_t hmac_key[RPMC_HMACKEY_SIZE] = {};
	rpmc_read_mc_status_t rpmc_read_status;

	if (0 != _sf_lib.rpmc_get_root_key(root_key, key_data)) {
		return SECUREFLASH_BD_ERROR_RPMC_UPDATE_HMAC_KEY;
	}

	status = _rpmc_hmac_sha256(root_key, key_data, RPMC_HMAC_KEY_DATA_SIZE, hmac_key);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}

	message[0] = RPMC_INST1;
	message[1] = RPMC_CMD_HMAC_KEY;
	message[2] = mc_address;
	message[3] = RPMC_RESERVED;
	memcpy(message + 4, key_data, RPMC_HMAC_KEY_DATA_SIZE);

	status = _rpmc_hmac_sha256(hmac_key, message, message_len, signature);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}	
	
	if (0 != _sf_lib.rpmc_update_hmac_key(RPMC_INST1, RPMC_CMD_HMAC_KEY, mc_address, RPMC_RESERVED, key_data, signature)) {
		return SECUREFLASH_BD_ERROR_RPMC_WRITE_ROOT_KEY;
	}

	return _rpmc_read_mc_status((&rpmc_read_status);
}

int SecureFlashBlockDevice::rpmc_request_mc(uint8_t mc_address, uint8_t *mc)
{
	int status = SECUREFLASH_BD_ERROR_OK;	
	uint8_t hmac_key[RPMC_HMAC_KEY_SIZE];
	uint8_t message[RPMC_INST_SIZE + PMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_TAG_SIZE];
	uint8_t message_len = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_TAG_SIZE;
	uint8_t signature[RPMC_SIGNATURE_SIZE] = {};
	uint8_t tag[RPMC_TAG_SIZE] = {};
	rpmc_read_mc_status_t rpmc_read_status;
	
	if (0 != _sf_lib.rpmc_get_hmac_key(mc_address, hmac_key)) {
		return SECUREFLASH_BD_ERROR_RPMC_REQUEST_MC;
	}

	message[0] = RPMC_INST1;
	message[1] = RPMC_CMD_REQUEST_MC;
	message[2] = mc_address;
	message[3] = RPMC_RESERVED;
	memcpy(message + 4, tag, RPMC_TAG_SIZE);
	status = _rpmc_hmac_sha256(hmac_key, message, message_len, signature);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}

	if (0 != _sf_lib.rpmc_request_mc(RPMC_INST1, RPMC_CMD_REQUEST_MC, mc_address, RPMC_RESERVED, tag, signature)) {
		return SECUREFLASH_BD_ERROR_RPMC_REQUEST_MC;
	}

	return _rpmc_read_mc_status((&rpmc_read_status);
}

int SecureFlashBlockDevice::rpmc_incr_mc(uint8_t mc_address)
{
	int status = SECUREFLASH_BD_ERROR_OK;	
	uint8_t mc[RPMC_MC_DATA_SIZE];
	uint8_t hmac_key[RPMC_HMAC_KEY_SIZE];
	uint8_t message[RPMC_INST_SIZE + PMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_MC_DATA_SIZE];
	uint8_t message_len = RPMC_INST_SIZE + RPMC_COMMAND_SIZE + RPMC_MC_ADDRESS_SIZE + RPMC_RESERVED_SIZE + RPMC_MC_DATA_SIZE;
	uint8_t signature[RPMC_SIGNATURE_SIZE] = {};
	

	status = rpmc_request_mc(mc_address, mc);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}

	if (0 != _sf_lib.rpmc_get_hmac_key(mc_address, hmac_key)) {
		return SECUREFLASH_BD_ERROR_RPMC_INCREMENT_MC;
	}

	message[0] = RPMC_INST1;
	message[1] = RPMC_CMD_INCREMENT_MC;
	message[2] = mc_address;
	message[3] = RPMC_RESERVED;
	memcpy(message + 4, mc, RPMC_MC_DATA_SIZE);
	status = _rpmc_hmac_sha256(hmac_key, message, message_len, signature);
	if (SECUREFLASH_BD_ERROR_OK != status) {
		return status;
	}

	if (0 != _sf_lib.rpmc_increment_mc(RPMC_INST1, RPMC_CMD_INCREMENT_MC, mc_address, RPMC_RESERVED, mc, signature)) {
		return SECUREFLASH_BD_ERROR_RPMC_INCREMENT_MC;
	}
	return _rpmc_read_mc_status((&rpmc_read_status);
}

int SecureFlashBlockDevice::rpmc_read_mc_status(rpmc_read_mc_status_t *rpmc_read_mc_status);
{	
	if (0 != _sf_lib.read_mc_status(RPMC_INST2, (uint8_t *)rpmc_read_mc_status)) {
		return SECUREFLASH_BD_ERROR_RPMC_INCREMENT_MC;
	}
	return SECUREFLASH_BD_ERROR_OK;
}

bd_size_t SecureFlashBlockDevice::get_read_size() const
{
	return _sf_lib.get_read_size();
}

bd_size_t SecureFlashBlockDevice::get_program_size() const
{
	return _sf_lib.get_program_size();
}

bd_size_t SecureFlashBlockDevice::get_erase_size() const
{
	return _sf_lib.get_min_erase_size();
}

bd_size_t SecureFlashBlockDevice::size() const
{
    if (!_is_initialized) {
        return 0;
    }

	return _sf_lib.get_density();
}

const char *SecureFlashBlockDevice::get_type() const
{
	return "SECUREFLASH";
}

// int SecureFlashBlockDevice::_check_authen_alg(AuthenEnum authen)
// {
// 	switch (authen) {
// 	case AUTHEN_AES_CCM_256:
// 	case AUTHEN_AES_CCM_192:
// 	case AUTHEN_AES_CCM_128:
// #ifdef MBEDTLS_CCM_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case AUTHEN_AES_GCM_128:
// 	case AUTHEN_AES_GCM_192:
// 	case AUTHEN_AES_GCM_256:
// #ifdef MBEDTLS_GCM_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case AUTHEN_HMAC_SHA_1:
// 	case AUTHEN_HMAC_SHA_256:
// 	case AUTHEN_HMAC_SHA_384:
// 	case AUTHEN_HMAC_SHA_512:
// #ifdef MBEDTLS_HMAC_DRBG_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case AUTHEN_AES_CMAC_128:
// 	case AUTHEN_AES_CMAC_256:
// #ifdef MBEDTLS_CMAC_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case AUTHEN_AES_GMAC_128:
// 	case AUTHEN_AES_GMAC_256:
// #ifdef MBEDTLS_GMAC_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	default:
// 		return FALSE;
// 	}
// 	return FALSE;
// }

// int SecureFlashBlockDevice::_check_encryption_alg(AuthenEnum authen)
// {
// 	switch (authen) {
// 	case ENC_AES_CCM_128:
// 	case ENC_AES_CCM_192:
// 	case ENC_AES_CCM_256:
// #ifdef MBEDTLS_CCM_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case ENC_AES_GCM_128:
// 	case ENC_AES_GCM_192:
// 	case ENC_AES_GCM_256:
// #ifdef MBEDTLS_GCM_C
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case ENC_AES_ECB_128:
// 	case ENC_AES_ECB_192:
// 	case ENC_AES_ECB_256:
// 		return TRUE;
// 	case ENC_AES_CBC_128:
// 	case ENC_AES_CBC_192:
// 	case ENC_AES_CBC_256:
// #ifdef MBEDTLS_CIPHER_MODE_CBC
// 		return TRUE;
// #else
// 		return FALSE;
// #endif

// 	case ENC_AES_OFB_128:
// 	case ENC_AES_OFB_192:
// 	case ENC_AES_OFB_256:
// #ifdef MBEDTLS_CIPHER_MODE_OFB
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	case ENC_AES_CTR_128:
// 	case ENC_AES_CTR_192:
// 	case ENC_AES_CTR_256:
// #ifdef MBEDTLS_CIPHER_MODE_CTR
// 		return TRUE;
// #else
// 		return FALSE;
// #endif
// 	default:
// 		return FALSE;
// 	}
// 	return FALSE;
// }


// int SecureFlashBlockDevice::_check_cipher_suite_sup(cipher_suite_t *cipher_suite)
// {
// 	if (FALSE == _check_authen_alg(cipher_suite->device_authen))
// 		return SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP;
// 	if (FALSE == _check_authen_alg(cipher_suite->message_authen))
// 		return SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP;
// 	if (FALSE == _check_encryption_alg(cipher_suite->message_encryption))
// 		return SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP;
// 	if (FALSE == _check_encryption_alg(cipher_suite->nonce_derivation))
// 		return SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP;
// 	return SECUREFLASH_BD_ERROR_OK;
// }

// void SecureFlashBlockDevice::_get_secure_flash_profile()
// {
// 	_sf_lib.get_secure_flash_profile(&_sf_profile);
// }

// int SecureFlashBlockDevice::_set_secure_flash_profile()
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	int n;
	
// 	for (n = 0; n < (_sf_profile.cipher_suite.number; n++) {
// 		status = _check_cipher_suite_sup(&_sf_profile.cipher_suite.cs[n]);
// 		if (SECUREFLASH_BD_ERROR_OK == status) {
// 			_sf_profile.cipher_suite_sel = n;
// 			break;
// 		}
// 	}
// 	return status;	
// }

// int SecureFlashBlockDevice::_negotiate_secure_profile()
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;

// 	_get_secure_flash_profile();

// 	status = _set_secure_flash_profile();
// 	if (SECUREFLASH_BD_ERROR_OK != status) {
// 		return status;
// 	}

// 	return status;
// }

// void SecureFlashBlockDevice::_check_preshare_key()
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;

// 	switch (_sf_equip.cipher_suite.preshare_key_gen) {
// 	case PSKG_SYMMETRIC_KEY:
// 		/* set the pre-share key by default definition */
// 		memcpy(_sf_equip.preshare_key, DEFAULT_PRESHARE_KEY[n], _sf_profile.miscellaneous.preshare_key_len);
// 		status = _sf_lib.update_preshare_key(_sf_equip.preshare_key, 0);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return status;
// 		}
// 		break;
// 	default:
// 		/* TODO: implementation of related key derivations */
// 		break;
// 	}
// 	return status;
// }

// void SecureFlashBlockDevice::_check_session_key(uint8_t key_id, uint8_t *salt, uint8_t salt_len, uint8_t *adata, uint8_t adata_len)
// {
// 	int status = SECUREFLASH_BD_ERROR_OK;
// 	hkdf_params_t hkdf_params = {
// 			.salt = salt, .salt_len = salt_len,
// 			.ikm = _sf_equip.preshare_key, .ikm_len = _sf_profile.miscellaneous.preshare_key_len,
// 			.info = adata, .info_len = adata,
// 			.okm = _sf_equip.session_key[key_id], .okm_len = _sf_profile.miscellaneous.session_key_len,
// 	};

// 	if (SSKG_NOT_SUP == _sf_equip.cipher_suite.session_key_gen) {
// 		status = _gen_key_by_hkdf(&hkdf_params);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return status;
// 		}
// 		status = _sf_lib.update_session_key(_sf_equip.session_key[key_id], key_id);
// 		if (SECUREFLASH_BD_ERROR_OK != status) {
// 			return status;
// 		}
// 	} else {
// 		/* TODO: implementation of related key derivations */
// 	}
// 	return status;
// }

// int SecureFlashBlockDevice::_gen_key_by_hkdf(hkdf_params_t *hkdf_params)
// {
//     mbedtls_md_type_t md_type;
//     const mbedtls_md_info_t *md;

//     if (hkdf_params->okm_len > (255 * (512 / 8))) {
//     	MX_ERR("okm length(%llu-bits) is not support\r\n", hkdf_params->okm_len * 8);
//         return SECUREFLASH_BD_ERROR_HKDF;
//     } else if (hkdf_params->okm_len > (255 * (384 / 8))) {
//     	MX_DBG("Use SHA512 for HKDF\r\n");
//         md_type = MBEDTLS_MD_SHA512;
//     } else if (hkdf_params->okm_len > (255 * (256 / 8))) {
//     	MX_DBG("Use SHA384 for HKDF\r\n");
//         md_type = MBEDTLS_MD_SHA384;
//     } else {
//     	MX_DBG("Use SHA256 for HKDF\r\n");
//         md_type = MBEDTLS_MD_SHA256;
//     }

//     md = mbedtls_md_info_from_type( md_type );

//     if (mbedtls_hkdf(md, hkdf_params->salt, hkdf_params->salt_len,
//     		hkdf_params->ikm, hkdf_params->ikm_len,
// 			hkdf_params->info, hkdf_params->info_len,
// 			hkdf_params->okm, hkdf_params->okm_len))
//         return SECUREFLASH_BD_ERROR_HKDF;
//     return SECUREFLASH_BD_ERROR_OK;
// }

int SecureFlashBlockDevice::set_config(uint8_t *cfg_blob, uint8_t *cfg_mask)
{
	if (SECUREFLASH_BD_ERROR_OK != _sf_lib.set_all_sfconfig(cfg_blob, cfg_mask))
		return SECUREFLASH_BD_ERROR_SET_CONFIG;
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::get_config(uint8_t *cfg_buf)
{
	MBED_ASSERT(cfg_buf);

	if (SECUREFLASH_BD_ERROR_OK != _sf_lib.get_all_sfconfig(cfg_buf, SECURE_FLASH_VERBOSE)) {
		return SECUREFLASH_BD_ERROR_GET_CFG;
	}
	// _sf_lib.get_authen_list(&_authen_list);
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::get_mc(uint8_t mc_id, uint8_t *mc)
{
	// int status = SECUREFLASH_BD_ERROR_OK;

	// status = _sf_lib.get_mc(mc_id, mc);
	// if (SECUREFLASH_BD_ERROR_OK != status) {
	// 	return status;
	// }
	// status = _encryption_func(NULL);
	// if (SECUREFLASH_BD_ERROR_OK != status) {
	// 	return status;
	// }
	// _sf_lib.sync_mc(mc_id, mc);
	// return status;
	return SECUREFLASH_BD_ERROR_OK;
}

int SecureFlashBlockDevice::increase_mc(uint8_t mc_id, uint8_t *mc)
{
	// int status = SECUREFLASH_BD_ERROR_OK;

	// status = _sf_lib.increase_mc(mc_id, mc);
	// if (SECUREFLASH_BD_ERROR_OK != status) {
	// 	return status;
	// }
	// status = _encryption_func(NULL);
	// if (SECUREFLASH_BD_ERROR_OK != status) {
	// 	return status;
	// }
	// switch (_sf_lib.manufacture_id) {
	// case MFR_ID_MACRONIX:
	// 	if (ENCRYPT_MAC == _sf_lib.security_data.ccm_gcm_params.security_operation) {
	// 		memcpy(mc, _sf_lib.security_data.ccm_gcm_params.data, spf.sym_enc.mc_len);
	// 	}
	// 	break;
	// default:
	// 	break;
	// }

	// _sf_lib.sync_mc(mc_id, mc);
	// return status;
	return SECUREFLASH_BD_ERROR_OK;
}
