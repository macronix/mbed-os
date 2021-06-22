#ifndef MBED_MXIC_PROVISION_DATA_H
#define MBED_MXIC_PROVISION_DATA_H

#include "mxic_sf_library_config.h"

#define PROVISION_DATA_SIZE_DEFAULT 0x400
#define PROVISION_DATA_ADDRESS (MBED_ROM_START + MBED_ROM_SIZE - PROVISION_DATA_SIZE_DEFAULT)

typedef enum {
    PROVISION_VENDOR_CERT,
    PROVISION_APP_CERT,
    PROVISION_PRIV_DATA,
} EnumProvisionType;

typedef struct {
    uint64_t app_id;
    uint8_t key_id;
    uint8_t datazone_id;
    uint8_t pub_key[65];
} app_meta_t;

typedef struct {
    EnumProvisionType type;
    uint8_t pub_key[65];
} vendor_data_t;

typedef struct {
    EnumProvisionType type;
    uint8_t app_num;
    app_meta_t app_meta[ARMOR_DATAZONE_NUM];
} app_data_t;

typedef struct {
    vendot_data_t vendor;
    app_data_t app    
} provision_data_t;

typedef struct {
    struct {		
        uint32_t len;
        secure_flash_profile_t secure_flash_profile;
        secure_flash_region_t region;			
        data_isolation_t data_isolation;
        struct {
            uint32_t len;
            uint8_t value[65];
        } rot_pub_key;			
    } message;

    struct {
        uint32_t len;
        uint8_t value[32];
        EncryptionEnum encryption;
    } signature;		
} priv_provision_data_t;

#endif