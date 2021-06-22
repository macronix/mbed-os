#ifndef MBED_SF_TRANSPORT_CONFIG_H
#define MBED_SF_TRANSPORT_CONFIG_H

    #include "rpmc_packet.h"

    #ifdef TARGET_MACRONIX_SECUREFLASH
       #include "MACRONIX/mxic_sf_transport_config.h"
    #else
        typedef struct {
            void *priv;
        } secure_write_packet_t;

        typedef struct {
            void *priv;
        } secure_read_packet_t;
    #endif
#endif