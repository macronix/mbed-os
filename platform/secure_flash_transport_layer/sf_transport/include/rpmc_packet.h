#ifndef MBED_SF_PACKET_H
#define MBED_SF_PACKET_H

#define RPMC_PKT_INST_SIZE 1
#define RPMC_PJT_COMMAND_SIZE 1
#define RPMC_PKT_DUMMY_CUCLE 1
#define RPMC_PKT_MC_STATUS 1
#define RPMC_PKT_TAG_SIZE 12
#define RPMC_PKT_MC_DATA_SIZE 4
#define RPMC_PKT_MC_ADDR_SIZE 1
#define RPMC_PKT_RESERVED_SIZE 1
#define RPMC_PKT_DATA_SIGNATURE_SIZE 60
#define RPMC_PKT_ROOT_KEY_SIZE 32
#define RPMC_PKT_HMAC_KEY_DATA_SIZE 4
#define RPMC_PKT_TRUNCATED_SIGNATURE_SIZE 28
#define RPMC_PKT_SIGNATURE_SIZE 32

struct {
    uint8_t inst;
    uint8_t dummy_cycle;
    struct {
        uint8_t mc_status;        
    } data;
} rpmc_read_status_packet_t;

struct {
    uint8_t inst;
    uint8_t dummy_cycle;
    struct {
        uint8_t mc_status;
        uint8_t tag[RPMC_PKT_TAG_SIZE];
        uint8_t mc_data[RPMC_PKT_MC_DATA_SIZE];
        uint8_t signature[RPMC_PKT_SIGNATURE_SIZE];
    } data;
} rpmc_read_data_status_packet_t;

struct {
    uint8_t inst;    
    struct {
        uint8_t command;
        uint8_t mc_address;
        uint8_t reserved;
        uint8_t root_key[RPMC_PKT_ROOT_KEY_SIZE];
        uint8_t truncated_signature[RPMC_PKT_TRUNCATED_SIGNATURE_SIZE];
    } data;
} rpmc_write_root_ket_packet_t;

struct {
    uint8_t inst;    
    struct {
        uint8_t command;
        uint8_t mc_address;
        uint8_t reserved;
        uint8_t KeyData[RPMC_PKT_HMAC_KEY_DATA_SIZE];
        uint8_t signature[RPMC_PKT_SIGNATURE_SIZE];
    } data;
} rpmc_update_hmac_ket_packet_t;

struct {
    uint8_t inst;    
    struct {
        uint8_t command;
        uint8_t mc_address;
        uint8_t reserved;
        uint8_t mc[RPMC_PKT_MC_DATA_SIZE];
        uint8_t signature[RPMC_PKT_SIGNATURE_SIZE];
    } data;
} rpmc_increment_mc_packet_t;

struct {
    uint8_t inst;
    struct {
        uint8_t command;
        uint8_t mc_address;
        uint8_t reserved;
        uint8_t tag[RPMC_PKT_TAG_SIZE];
        uint8_t signature[RPMC_PKT_SIGNATURE_SIZE];
    } data;
} rpmc_request_mc_packet_t

#endif