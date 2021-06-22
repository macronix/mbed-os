#ifndef MBED_SECURE_FLASH_BLOCK_DEVICE_H
#define MBED_SECURE_FLASH_BLOCK_DEVICE_H

#if !defined(DEVICE_SPI) && !defined(DEVICE_QSPI) && !defined(DEVICE_OSPI)
#error "DEVICE_SPI, DEVICE_QSPI and DEVICE_OSPI are not defined!"
#endif

#include "sf_library.h"
#include "blockdevice/BlockDevice.h"
#include "rpmc.h"

#if defined(DEVICE_SPI)
#include "drivers/SPI.h"
#elif defined(DEVICE_QSPI)
#inlcude "drivers/QSPI.h"
#elif defined(DEVICE_OSPI)
#inlcude "drivers/OSPI.h"
#endif

#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO0
#define MBED_CONF_SECUREFLASH_DRIVER_IO0 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO1
#define MBED_CONF_SECUREFLASH_DRIVER_IO1 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO2
#define MBED_CONF_SECUREFLASH_DRIVER_IO2 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO3
#define MBED_CONF_SECUREFLASH_DRIVER_IO3 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO4
#define MBED_CONF_SECUREFLASH_DRIVER_IO4 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO5
#define MBED_CONF_SECUREFLASH_DRIVER_IO5 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO6
#define MBED_CONF_SECUREFLASH_DRIVER_IO6 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_IO7
#define MBED_CONF_SECUREFLASH_DRIVER_IO7 NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_CLK
#define MBED_CONF_SECUREFLASH_DRIVER_CLK NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_CS
#define MBED_CONF_SECUREFLASH_DRIVER_CS NC
#endif
#ifndef MBED_CONF_SECUREFLASH_DRIVER_DQS
#define MBED_CONF_SECUREFLASH_DRIVER_DQS NC
#endif
#ifndef MBED_CONF_SECUREFLASH_POLARITY_MODE
#define MBED_CONF_SECUREFLASH_POLARITY_MODE 0
#endif

#ifndef MBED_CONF_SECUREFLASH_DRIVER_FREQ
#define MBED_CONF_SECUREFLASH_DRIVER_FREQ 40000000
#endif

// int ecdsa_verify_key_from_bin(uint8_t *message, size_t messae_len, 
// 		uint8_t *pub_key, size_t pub_key_len, uint8_t *sig, size_t sig_len);

/** Enum SecureFlash standard error codes
 *
 *  @enum SecureFlash_bd_error
 */
enum secureflash_bd_error {
    SECUREFLASH_BD_ERROR_OK                    = 0,     /*!< no error */
	SECUREFLASH_BD_ERROR_PARSING_FAILED        = -4002, /* SFDP Parsing failed */
	SECUREFLASH_BD_ERROR_READY_FAILED          = -4003, /* Wait for Memory Ready failed */
	SECUREFLASH_BD_ERROR_WREN_FAILED           = -4004, /* Write Enable Failed */
	SECUREFLASH_BD_ERROR_INVALID_ERASE_PARAMS  = -4005, /* Erase command not on sector aligned addresses or exceeds device size */
	SECUREFLASH_BD_ERROR_INIT                  = -4006, /*!< device specific error -4001 */
	SECUREFLASH_BD_ERROR_DEINIT                = -4007, /*!< device specific error -4001 */
	SECUREFLASH_BD_ERROR_READ                  = -4008, /*!< device specific error -4001 */
	SECUREFLASH_BD_ERROR_PROGRAM               = -4009, /*!< device specific error -4001 */
	SECUREFLASH_BD_ERROR_ERASE                 = -4010, /*!< device specific error -4001 */
	SECUREFLASH_BD_SESSION_ALG_NOT_SUPPORT     = -4011,
	SECUREFLASH_BD_ERROR_SYM_SECURITY_FUNC     = -4012,
	SECUREFLASH_BD_ERROR_ACCESS_ADDR_EXCEEDED  = -4013,
	SECUREFLASH_BD_ERROR_NO_DEFINITION         = -4014,
	SECUREFLASH_BD_ERROR_ALLOC                 = -4015,
	SECUREFLASH_BD_ERROR_SET_CFG               = -4016,
	SECUREFLASH_BD_ERROR_GET_CFG               = -4017,
	SECUREFLASH_BD_ERROR_BOOSTRAP              = -4019,
	SECUREFLASH_BD_ERROR_SET_CONFIG            = -4019,
	SECUREFLASH_BD_ERROR_HKDF                  = -4020,
	SECUREFLASH_BD_ERROR_SET_SYM_KEY           = -4021,
	SECUREFLASH_BD_ERROR_LKD_CFG_REG           = -4022,
	SECUREFLASH_BD_ERROR_LKD_KEY_REG           = -4023,
	SECUREFLASH_BD_ERROR_LKD_IND_KEY           = -4024,
	SECUREFLASH_BD_ERROR_MC                    = -4025,
	SECUREFLASH_BD_ERROR_WR_RD_SECURE_PKT      = -4026,
	SECUREFLASH_BD_ERROR_MBEDTLS_ENCRYPTION    = -4027,
	SECUREFLASH_BD_ERROR_DEV_AUTHEN            = -4028,
	SECUREFLASH_BD_ERROR_MSG_AUTHEN            = -4029,
	SECUREFLASH_BD_ERROR_PROVISION             = -4030,
	SECUREFLASH_BD_ERROR_CIPHER_SUITE_NOT_SUP  = -4031,
	SECUREFLASH_BD_ERROR_SESSION_EXHAUST       = -4032,
	SECUREFLASH_BD_ERROR_SESSION_IN_USE        = -4033,
	SECUREFLASH_BD_ERROR_AUTHEN                = -4034,
	SECUREFALSH_BD_ERROR_ENCRYPTION_NOT_SUP    = -4035,
	SECUREFALSH_BD_ERROR_ENCRYPTION_GET_KEY    = -4036,
	SECUREFALSH_BD_ERROR_ENCRYPTION_GET_TAG    = -4036,
	SECUREFALSH_BD_ERROR_PREPARE_SECURE_PACKET = -4037,
	SECUREFALSH_BD_ERROR_AUTHEN_BY_DEVICE      = -4038,
	SECUREFALSH_BD_ERROR_AUTHEN_BY_HOST        = -4039,	
	SECUREFLASH_BD_ERROR_ECDSA_GENKEY          = -4040,
	SECUREFLASH_BD_ERROR_CHECK_PROVISION       = -4041,
	SECUREFLASH_BD_ERROR_WRITE_PROVISION       = -4042,
	SECUREFLASH_BD_ERROR_READ_PROVISION        = -4042,
	SECUREFLASH_BD_ERROR_LOCK_PROVISION        = -4043,
	SECUREFLASH_BD_ERROR_ECDSA_VERIFY          = -4044,
	SECUREFLASH_BD_ERROR_NEED_ATTESTATION      = -4045,
	SECUREFLASH_BD_ERROR_CLOSE_SESSION         = -4046,
	SECUREFLASH_BD_ERROR_SESSION_ID_NOT_EXIST  = -4047,
	SECUREFLASH_BD_ERROR_THREAD_ID_NOT_EXIST   = -4048,
	SECUREFLASH_BD_ERROR_ATTESTATION_CHALLENGE = -4049,
	SECUREFLASH_BD_ERROR_ATTESTATION_NOT_READY = -4050,
	SECUREFLASH_BD_ERROR_RPMC_WRITE_ROOT_KEY   = -4051,
	SECUREFLASH_BD_ERROR_RPMC_UPDATE_HMAC_KEY  = -4052,
	SECUREFLASH_BD_ERROR_RPMC_REQUEST_MC       = -4053,
	SECUREFLASH_BD_ERROR_RPMC_INCREMENT_MC     = -4054,
	SECUREFLASH_BD_ERROR_GET_SSESSION_ID       = -4055,	
	SECUREFLASH_BD_ERROR_NO_SECURITY_PERMISION = -4056,	
};

class SecureFlashBlockDevice : public mbed::BlockDevice {
public:
    SecureFlashBlockDevice(PinName io0 = MBED_CONF_SECUREFLASH_DRIVER_IO0,
    		PinName io1 = MBED_CONF_SECUREFLASH_DRIVER_IO1,
    		PinName io2 = MBED_CONF_SECUREFLASH_DRIVER_IO2,
    		PinName io3 = MBED_CONF_SECUREFLASH_DRIVER_IO3,
    		PinName io4 = MBED_CONF_SECUREFLASH_DRIVER_IO4,
    		PinName io5 = MBED_CONF_SECUREFLASH_DRIVER_IO5,
    		PinName io6 = MBED_CONF_SECUREFLASH_DRIVER_IO6,
    		PinName io7 = MBED_CONF_SECUREFLASH_DRIVER_IO7,
    		PinName clk = MBED_CONF_SECUREFLASH_DRIVER_CLK,
    		PinName cs = MBED_CONF_SECUREFLASH_DRIVER_CS,
    		PinName dqs = MBED_CONF_SECUREFLASH_DRIVER_DQS,
    		int clock_mode = MBED_CONF_SECUREFLASH_POLARITY_MODE,
    		int freq = MBED_CONF_SECUREFLASH_DRIVER_FREQ);

    ~SecureFlashBlockDevice()
    {
        deinit();
    }

    virtual int init();
    virtual int deinit();
	
	int write_provision(void *provision_data);
	int read_provision(void *provision_data);
	int lock_provision(void *provision_data);
    
	int open_session(uint64_t session_id, uint64_t app_id)
	int close_session(uint64_t session_id)
	int get_session_id(uint8_t *session_id)

	int attestation_get_challenge(uint8_t *challenge)
    int attestation_check_response(uint8_t *response)

    virtual int read(void *buffer, bd_addr_t addr, bd_size_t buffer_size);
    virtual int program(const void *buffer, bd_addr_t addr, bd_size_t buffer_size);
    virtual int erase(bd_addr_t addr, bd_size_t ers_size);

	int set_config(uint8_t *cfg_valid, uint8_t *cfg_mask);
    int get_config(uint8_t *cfg_buf);

    int get_uid(uint8_t *uid, bd_size_t size);
    int get_puf(uint8_t *puf, bd_size_t size);
    int get_trng(uint8_t *trng, bd_size_t size);

	int rpmc_write_root_key(uint8_t mc_id, uint8_t *root_key);
	int rpmc_update_hmac_key(uint8_t mc_id, uint8_t *salt_key);
	int rpmc_increase_mc(uint8_t mc_id, uint8_t *mc);
    int rpmc_get_mc(uint8_t mc_id, uint8_t *mc);
    
    virtual bd_size_t get_read_size() const;
    virtual bd_size_t get_program_size() const;
    virtual bd_size_t get_erase_size() const;
    virtual bd_size_t size() const;
    virtual const char *get_type() const;    

private:
	int _check_provision_data();    
    int _device_authen(encryption_indicator_t *indicator, command_params_t *cmd_params);
    int _message_authen(encryption_indicator_t *indicator, command_params_t *cmd_params);
    int _read_operation(uint8_t *buffer, bd_addr_t addr, bd_size_t buffer_size);
    int _program_operation(uint8_t *buffer, bd_addr_t addr, bd_size_t buffer_size);
    int _erase_operation(bd_addr_t addr);
	int _security_operation(command_params_t *cmd_params);
	int _check_authen_by_device(encryption_requirement_t *enc_req, command_params_t *cmd_params);
	int _check_authen_by_host(encryption_requirement_t *enc_req, command_params_t *cmd_params);
	int _check_encryption(encryption_requirement_t *enc_req, command_params_t *cmd_params);
	int _get_ccm_params(encryption_indicator_t *indicator, command_params_t *cmd_params);
	int _encryption_exec(encryption_indicator_t *indicator);
	int _aes_ccm_exec(encryption_indicator_t *indicator);
    int _aes_ecb_exec(encryption_indicator_t *indicator);
	int _aes_ecdsa_exec(encryption_indicator_t *indicator);
	int _ecdsa_secp256r1_verify(uint8_t *message, bd_size_t messae_len, uint8_t *pub_key, uint8_t *sig);

    static SingletonPtr<PlatformMutex> _mutex;

    unsigned int _address_size; // number of bytes for address
	uint32_t _init_ref_count;
	bool _is_initialized;

	SECURE_FLASH_TYPE _flash;
	SecureFlashLib _sf_lib;
	// security_data_t _security_data;
	secure_flash_profile_t _sf_profile;
	// secure_flash_equipment_t _sf_equip;	
};

#endif
