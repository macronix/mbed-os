#ifndef MBED_SECURE_FLASH_API_H
#define MBED_SECURE_FLASH_API_H

#include <stdint.h>
#include "secureflash_encryption_alg.h"
#include "sf_transport.h"
#include "sf_library_config.h"

typedef enum {	
	CMDNAME_READ,
	CMDNAME_PROGRAM,
	CMDNAME_ERASE,
	CMDNAME_RD_UID,
	CMDNAME_RD_PUF,
	CMDNAME_RD_TRNG,
	CMDNAME_WR_ROOT_KEY,
	CMDNAME_UPDATE_HMAC_KEY,
	CMDNAME_RD_MC,
	CMDNAME_INCR_MC,
	CMDNAME_VENDOR,	
	CMDNAME_MAX,
} CmdNameEnum;

// typedef struct {
// 	union {
		// struct {
		// 	uint64_t addr;
		// 	uint8_t *buf;
		// 	uint64_t size;
		// } read;
		// struct {
		// 	uint64_t addr;
		// 	uint8_t *buf;
		// 	uint64_t size;
		// } program;
		// struct {
		// 	uint64_t addr;
		// 	uint64_t size;
		// } erase;
		// struct {
		// 	uint8_t *buf;
		// 	uint64_t size;
		// } rd_puf;

		// struct {
		// 	uint8_t *buf;
		// 	uint64_t size;
		// } rd_uid;

		// struct {
		// 	uint8_t *buf;
		// 	uint64_t size;
		// } rd_trng;

		// struct {
		// 	uint8_t *buf;
		// 	uint64_t size;
		// 	uint8_t id;			
		// // } rd_mc;

		// struct {
		// 	uint8_t id;
		// } incr_mc;

typedef struct {
	CmdNameEnum name;
	uint8_t id;
	uint64_t address;		
	uint8_t *idata;
	uint8_t *odata;		
	uint64_t idata_len;
	uint64_t odata_len;
	uint8_t app_id;
	secure_write_packet_t write_packet;
	secure_read_packet_t read_packet;
}command_params_t;

typedef struct encryption_indicator_t{
	union {
		struct {
			uint8_t *key;
			uint8_t key_len;
			uint8_t *iv;
			uint8_t iv_len;
			uint8_t *add;
			uint8_t add_len;			
			uint8_t *tag;
			uint8_t tag_len;
			uint8_t *idata;
			uint8_t *odata;
			uint8_t data_len;
			struct encryption_indicator_t *iv_enc;
		} aes_ccm_gcm;
		struct {
			uint8_t *key;
			uint8_t key_len;
			uint8_t *idata;
			uint8_t *odata;
			uint8_t data_len;
		} aes_ecb;
		struct {
			uint8_t *pub_key;
			uint32_t pub_key_len;
			uint8_t *pri_key;
			uint32_t pri_key_len;
			uint8_t *hash;
			uint8_t *signature;
			uint8_t signature_len;			
			uint8_t *message;
			uint32_t message_len;
		} ecdsa;
		struct {
			uint8_t *key;
			uint32_t key_len;
			uint8_t *idata;
			uint8_t *odata;
			uint32_t data_len			
		} hmac;
	};
	EncryptionAlgorithmEnum algorithm;
	EncryptionOperationEnum operation;	
} encryption_indicator_t;

typedef struct {
	uint8_t key_exchange;
	uint8_t key_derive;
	uint8_t mac;
	uint8_t cipher;	
	uint8_t api_signature;
	uint8_t provision_data_signature;
} cipher_suite_t;

typedef struct {
	CmdNameEnum cmd_name;
	EncryptionAlgorithmEnum write_packet_alg;
	EncryptionOperationEnum write_packet_op;
	EncryptionAlgorithmEnum read_packet_alg;
	EncryptionOperationEnum read_packet_op;
} command_requirement_t;

typedef struct {
	uint8_t is_provisioning_done:  1,
			cipher_suite_sel: 3;
	uint32_t provisioning_data_addr;

	struct {
		uint8_t rng:1,
				uid:1,
				puf:1,
				rpmc:1,
				attestation:1;
	} capabilities;

	struct {
		uint8_t number;
		cipher_suite_t index[4];
	} cipher_suite;

	struct {
		uint8_t number;
		command_requirement_t index[CMDNAME_MAX];
	} command_requirement;
} secure_flash_profile_t;

// /* session related */
// typedef struct session_t{	
// 	uint8_t session_id;
// 	uint8_t datazone_id;
// 	uint8_t key_id;
// 	session_t *next;
// 	session_t *prev;
// } secure_flash_session_t;

// typedef struct {
// 	secure_flash_session_t *head;
// 	uint8_t max_num;
// 	uint8_t using_num;
// } session_pool_t;

class SecureFlashLib
{
public :
    SecureFlashLib(SECURE_FLASH_TYPE *flash, int freq);    

	secure_flash_profile_t secure_flash_profile;
	uint8_t manufacture_id;

    /* secure flash APIs   */
    int init();
    int deinit();

	int lock_provision_data(void *provision_data_input);
	int write_provision_data(void *provision_data_input);
	int read_provision_data(void *provision_data_input);
	int parse_provision_data(void *provision_data_input, encryption_indicator_t *indicator);

	int SecureFlashLib::get_challenge(uint64_t app_id, uint8_t *challenge);
	int SecureFlashLib::get_ecdsa_256r1_params(uint8_t *response, uint8_t *message, uint64_t *messgae_len, uint8_t *pub_key, uint8_t *sig);
	
		
    int default_provisioning();
    int (*specified_provisioning)();
    void get_secure_flash_profile(secure_flash_profile_t *sf_profile);
    int set_cipher_suite(cipher_suite_t *cipher_suite);    


    int switch_security_field(uint8_t enter_secure_field);

	int get_ccm_params(encryption_indicator_t *indicator, command_params_t *cmd_params);
    int get_iv(encryption_indicator_t *indicator);

	int prepare_secure_write_packet(command_params_t *cmd_params, secure_write_packet_t *write_pkt);	
	
	int write_secure_packet(command_params_t *cmd_params);
	int read_secure_packet(command_params_t *cmd_params);

    int set_all_sfconfig(const uint8_t *cfg_blob, const uint8_t *cfg_mask);
    int get_all_sfconfig(uint8_t *buf, uint8_t verbose);    

    int get_trng(uint8_t *buf, uint8_t size, uint8_t *rtn_size);    
    void get_serial_number(uint8_t *buf, uint8_t size, uint8_t *rtn_size);

	int rpmc_write_root_key(uint8_t mc_id);
	int rpmc_update_hmac_key(uint8_t mc_id);
	int rpmc_read_mc(uint8_t mc_id);
	int rpmc_incr_mc(uint8_t mc_id);

    uint64_t get_density() const;
	uint64_t get_min_erase_size() const;
	uint64_t get_program_size() const;
	uint64_t get_read_size() const;

	int rpmc_write_root_key(uint8_t mc_id, uint8_t *root_key);
	int rpmc_update_hmac_key(uint8_t mc_id, uint8_t *hmac_key_data);
	int rpmc_request_mc(uint8_t mc_id, uint8_t *root_key);
	int rpmc_increment_mc(uint8_t mc_id, uint8_t *root_key);

private:

    uint64_t _density;
    uint64_t _security_field_density;

    SecureFlashTransport _sf_transport;	

    /****************************/
    /* secure flash Functions   */
    /****************************/
	int _prepare_secure_packet_read(command_params_t *cmd_params);
	int _prepare_secure_packet_program(command_params_t *cmd_params);
	int _prepare_secure_packet_erase(command_params_t *cmd_params);
	int _prepare_secure_packet_rd_uid(command_params_t *cmd_params);
	int _prepare_secure_packet_rd_trng(command_params_t *cmd_params);
	int _prepare_secure_packet_rd_puf(command_params_t *cmd_params);

	int _get_add(encryption_indicator_t *indicator, command_params_t *cmd_params);
	int _get_key(encryption_indicator_t *indicator, command_params_t *cmd_params);
	int _get_key_with_datazone_isolation(encryption_indicator_t *indicator, command_params_t *cmd_params);
	int _get_tag_data(encryption_indicator_t *indicator, command_params_t *cmd_params);
    int _get_iv_encryption_params(encryption_indicator_t **iv_indicator);
    int _get_nonce_from_host(uint8_t* input_nonce, uint8_t *output_nonce);
    int _get_nonce_from_flash(encryption_indicator_t *iv_indicator);
    int _internal_write_read_secure_packet(secure_packet_t *secure_packet);
    int _get_security_field_info();        
    int _get_add(encryption_indicator_t *indicator, command_params_t *cmd_params);
    int _get_macount(uint8_t *macount);

    int _set_sfconfig(uint32_t addr, const uint8_t *buf, uint32_t size);

    int _check_macount();
    int _check_nonce_random(uint8_t key_id);
    int _check_cmd_permit(uint8_t armor_inst, uint8_t target_id);

	int _check_imac_by_cmd(uint8_t armor_inst);
    int _check_key_id_by_cmd(uint8_t armor_inst, uint8_t target_id, uint8_t lkd_reg);
    uint8_t _set_op_by_mac_params(uint8_t inst, uint8_t op);
    int _parse_security_error_code(command_params_t *cmd_params);

    int _spi_write_key(uint8_t *input_key, uint8_t target_key_id);

    /****************************/
    /* secure flash Commands    */
    /****************************/
    int _armor_pgrd(uint32_t addr, uint8_t *buf, uint8_t size);
    int _armor_rgen(uint8_t *buf, uint8_t size);
    int _armor_ngen(uint8_t *in_data, uint8_t op, uint8_t *output_data, uint8_t size);
    int _armor_infrd(uint32_t addr, uint8_t *output_data, uint8_t size);

    int _armor_puftrans(uint8_t key_id);
    /********************************/
    /* standard NOR flash functions */
    /********************************/
    int _std_wren();
    int _std_program(uint32_t addr, const uint8_t *buf, uint8_t size);
    int _std_read(uint32_t addr, uint8_t *buf, uint8_t size);
    int _std_erase(uint32_t addr, uint8_t size);
    int _std_read_sr(uint8_t *status_reg, uint8_t size);
    int _std_read_scur(uint8_t *secure_reg, uint8_t size);
    int _std_read_cr(uint8_t *cr_reg, uint8_t size);
    int _std_read_id(uint8_t *id, uint8_t size);
    int _std_ensf();
    int _std_exsf();
    int _std_sw_reset();
    int _std_en4b();

    int _is_mem_ready();
	int _is_mem_ready_armor();
    int _check_wren();
    int _check_sr_crc();

    /*******************/
    /* Other functions */
    /*******************/
    void _generate_random_number(uint8_t *buf, uint8_t size);
    void _compute_crc(uint8_t data_len, uint8_t *data_buf, uint8_t* rtn_crc);
    void _set_vector();    
};



#endif
