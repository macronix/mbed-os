#ifndef MBED_SECURE_FLASH_CONFIGS_H
#define MBED_SECURE_FLASH_CONFIGS_H

#define DATAZONE_ISOLATION_MODULE

#define SECURE_FLASH_VERBOSE FALSE

#define MX_DBG printf
#define MX_INFO printf
#define MX_ERR printf

#define MX_TEMP printf

#ifdef TARGET_MACRONIX_SECUREFLASH
    #include "MACRONIX/mxic_sf_library_config.h"
#endif

#endif
