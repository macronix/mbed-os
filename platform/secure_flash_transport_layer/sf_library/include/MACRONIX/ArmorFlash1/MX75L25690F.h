#ifndef MBED_MX75L25690F_H
#define MBED_MX75L25690F_H

#include "../../secureflash_encryption_alg.h"

/* Secure Flash Commands */
#define ARMOR_INST_KGEN     0x04
#define ARMOR_INST_KWR      0x05
#define ARMOR_INST_ENCRD    0x0A
#define ARMOR_INST_PGRD     0x0C
#define ARMOR_INST_INFRD    0x0D
#define ARMOR_INST_ENCWR    0x0E
#define ARMOR_INST_NGEN     0x10
#define ARMOR_INST_RGEN     0x12
#define ARMOR_INST_MC       0x13
#define ARMOR_INST_LKD      0x14
#define ARMOR_INST_PUFRD    0x1A
#define ARMOR_INST_PUFTRANS 0x1B

/* security profile */
#define CAP_RNG_SUP   1
#define CAP_UID_SUP   1
#define CAP_PUF_SUP   1
#define CAP_RPMC_SUP  0

#define CIPHER_SUITE_KEY_EX  KEYEX_NOT_SUP
#define CIPHER_SUITE_KEY_DRV KEYDRV_NOT_SUP
#define CIPHER_SUITE_MAC     ENC_AES_CCM_256  
#define CIPHER_SUITE_CIPHER  ENC_AES_CCM_256  
#define CIPHER_SUITE_VENDOR0 ENC_AES_ECB										

#define ARMOR_READ_SIZE     32
#define ARMOR_PGM_SIZE      32
#define ARMOR_ERS_SIZE      (1<<12)

#define ARMOR_IV_FLAG       0x79
#define ARMOR_PUF_SIZE      32
#define ARMOR_TRNG_SIZE     32

#define TOP_BOTTOM_OFS      0x00400000

/* command option bits */

/* MAC parameters */
#define OP_MAC_NONE         0x00
#define OP_MAC_LINKED_MC    (1 << 5)
#define OP_MAC_SN           (1 << 6)
#define OP_MAC_EXTRAZONE    (1 << 7)

/* KGEN command option */
#define OP_KGEN_RESERVED    0x00
#define OP_KGEN_NVM_KEY     0x01

/* KWR command option */
#define OP_KWR_RESERVED     0x00
#define OP_KWR_NVM_KEY      0x01

/* ENCWR command option */
#define OP_ENCWR_PGM        0x00
#define OP_ENCWR_ERS_4K     0x01
#define OP_ENCWR_ERS_32K    0x02
#define OP_ENCWR_ERS_64K    0x03
#define OP_ENCWR_MASK       0x03

/* MC command option */
#define OP_MC_INCR          0x00
#define OP_MC_RD            0x01
#define OP_MC_INCR_RD_MASK  (1 << 0)
#define OP_MC_MAC_NOT_NEED  0x00
#define OP_MC_MAC_NEED      0x02
#define OP_MC_MAC_MASK      (1 << 1)

/* NGEN command option */
#define OP_NGEN_FROM_HOST    0x00
#define OP_NGEN_FROM_FLASH   0x01

/* LKD command option */
#define TARGET_LKD_CONFIG    0
#define TARGET_LKD_KEY       1
#define TARGET_LKD_EXTRAZONE 2
#define TARGET_LKD_MC        3
#define TARGET_LKD_PUF       4
#define TARGET_LKD_CERS      5
#define TARGET_LKD_DATAZONE  6
#define TARGET_LKD_IND_KEY   7
#define TARGET_DIS_IND_KEY   15

/* MC command target */
#define MC0                  0
#define MC1                  1
#define MC2                  2
#define MC3                  3

/* INFRD command, address of register */
#define ARMOR_INFRD_MACOUNT_ADDR 0x01

/* Secure filed configurations */
#define SECUREFIELD_CFG_ADDR_S    0x7FF000
#define SECUREFIELD_CFG_ADDR_E    0x7FF15F
#define SECUREFIELD_CFG_SIZE      (SECUREFIELD_CFG_ADDR_E - SECUREFIELD_CFG_ADDR_S + 1)

#define ARMOR_LKD_REG_SIZE        1
#define ARMOR_LKD_REG_MEM_ADDR    0x7FF040
#define ARMOR_LKD_REG_TOTAL_SIZE  (ARMOR_LKD_REG_SIZE * 6)
#define ARMOR_LKD_REG_MASK        0x03
#define ARMOR_LKD_REG_NOT_LKD     0x03
#define ARMOR_CFG_LKD_OFS         0
#define ARMOR_KEY_LKD_OFS         1
#define ARMOR_EXTRAZONE_LKD_OFS   2
#define ARMOR_CNT_LKD_OFS         3
#define ARMOR_PUF_LKD_OFS         4
#define ARMOR_CERS_LKD_OFS        5

#define ARMOR_SPAREZONE_SIZE      32
#define ARMOR_SPAREZONE_MEM_ADDR  0x7FF120

#define ARMOR_EXTRAZONE_SIZE      32
#define ARMOR_EXTRAZONE_MEM_ADDR  0x7FF140

#define ARMOR_SN_SIZE             8
#define ARMOR_SN_MEM_ADDR         0x7FF000

/* Data Zone */
#define ARMOR_DATAZONE_NUM                16
#define ARMOR_DATAZONE_SIZE               0x40000
#define ARMOR_DATAZONE_TOTAL_SIZE         (ARMOR_DATAZONE_SIZE * ARMOR_DATAZONE_NUM)
#define ARMOR_DATAZONE_MEM_ADDR           0x00000000
#define SECURE_MEM_SIZE                   ARMOR_DATAZONE_TOTAL_SIZE

#define ARMOR_DATAZONE_CFG_NUM            ARMOR_DATAZONE_NUM
#define ARMOR_DATAZONE_CFG_SIZE           4
#define ARMOR_DATAZONE_CFG_TOTAL_SIZE     (ARMOR_DATAZONE_CFG_SIZE * ARMOR_DATAZONE_CFG_NUM)
#define ARMOR_DATAZONE_CFG_MEM_ADDR       0x7FF080

/* Data Zone configuration */
#define  DATAZONE_CFG_BYTE_0              0
    #define DZ_CFG_RDID_OFS               4
    #define DZ_CFG_RDID_MASK              (0x03 << DZ_CFG_RDID_OFS)
#define  DATAZONE_CFG_BYTE_1              1
    #define DZ_CFG_WRID_OFS               0
    #define DZ_CFG_WRID_MASK              (0x03 << DZ_CFG_WRID_OFS)
    #define DZ_CFG_ENCRD_OFS              6
    #define DZ_CFG_ENCRD_MASK             (0x01 << DZ_CFG_ENCRD_OFS)
    #define DZ_CFG_ENCWR_OFS              7
    #define DZ_CFG_ENCWR_MASK             (0x01 << DZ_CFG_ENCWR_OFS)
#define  DATAZONE_CFG_BYTE_2              2
    #define DZ_CFG_SN_PERM_OFS            1
    #define DZ_CFG_SN_PERM_MASK           (0x01 << DZ_CFG_SN_PERM_OFS)
    #define DZ_CFG_EXTRA_PERM_OFS         2
    #define DZ_CFG_EXTRA_PERM_MASK        (0x01 << DZ_CFG_EXTRA_PERM_OFS)
    #define DZ_CFG_WRITE_PERM_OFS         3
    #define DZ_CFG_WRITE_PERM_MASK        (0x03 << DZ_CFG_WRITE_PERM_OFS)
    #define DZ_CFG_WRITE_PERM_INHIBIT     (0x01 << DZ_CFG_WRITE_PERM_OFS)
    #define DZ_CFG_WRITE_PERM_LKD_WO_IMAC (0x02 << DZ_CFG_WRITE_PERM_OFS)
    #define DZ_CFG_WRITE_PERM_LKD_W_IMAC  (0x03 << DZ_CFG_WRITE_PERM_OFS)
    #define DZ_CFG_MACID_OFS              6
    #define DZ_CFG_MACID_MASK             (0x03 << DZ_CFG_MACID_OFS)
#define DATAZONE_CFG_BYTE_3               3
    #define DZ_CFG_WRITE_LKD_OFS          0
    #define DZ_CFG_WRITE_LKD_MARK         (0x03 << DZ_CFG_WRITE_LKD_OFS)

/* Key */
#define ARMOR_KEY_NUM                  4
#define ARMOR_KEY_SIZE                 32
#define ARMOR_KEY_MEM_ADDR             0x7FF600

#define ARMOR_KEY_CFG_NUM              ARMOR_KEY_NUM
#define ARMOR_KEY_CFG_SIZE             4
#define ARMOR_KEY_CFG_TOTAL_SIZE       (ARMOR_KEY_CFG_SIZE * ARMOR_KEY_CFG_NUM)
#define ARMOR_KEY_CFG_MEM_ADDR         0x7FF0C0

/* Key configuration */
#define KEY_CFG_BYTE_0                 0
    #define KEY_CFG_KGEN_MAC_OFS       3
    #define KEY_CFG_KGEN_MAC_MASK      (0x01 << KEY_CFG_KGEN_MAC_OFS)
    #define KEY_CFG_MACID_OFS          4
    #define KEY_CFG_MACID_MASK         (0x03 << KEY_CFG_MACID_OFS)
    #define KEY_CFG_LIMIT_MC_OFS        7
    #define KEY_CFG_LIMIT_MC_MASK      (0x01 << KEY_CFG_LIMIT_MC_OFS)
#define KEY_CFG_BYTE_1                 1
    #define KEY_CFG_LINKED_KEY_OFS     0
    #define KEY_CFG_LINKED_KEY_MASK    (0x03 << KEY_CFG_LINKED_KEY_OFS)
    #define KEY_CFG_LINKED_MC_OFS      4
    #define KEY_CFG_LINKED_MC_MASK     (0x03 << KEY_CFG_LINKED_MC_OFS)
#define KEY_CFG_BYTE_2                 2
    #define KEY_CFG_TARGET_PERM_OFS    5
    #define KEY_CFG_TARGET_PERM_MASK   (1 << KEY_CFG_TARGET_PERM_OFS)
#define KEY_CFG_BYTE_3                 3
    #define KEY_CFG_IND_LKD_OFS        0
    #define KEY_CFG_IND_LKD_MASK       (0x03 << KEY_CFG_IND_LKD_OFS)
    #define KEY_CFG_IND_NOT_LKD        (0x03 << KEY_CFG_IND_LKD_OFS)
    #define KEY_CFG_IND_DIS_OFS        2
    #define KEY_CFG_IND_DIS_MASK       (0x03 << KEY_CFG_IND_DIS_OFS)
    #define KEY_CFG_IND_NOT_DIS        (0x03 << KEY_CFG_IND_DIS_OFS)
    #define KEY_CFG_NRANDOM_OFS        4
    #define KEY_CFG_NRANDOM_MASK       (1 << KEY_CFG_NRANDOM_OFS)
    #define KEY_CFG_PUFRD_PERM_OFS     5
    #define KEY_CFG_PUFRD_PERM_MASK    (1 << KEY_CFG_PUFRD_PERM_OFS)
    #define KEY_CFG_PUFTRANS_PERM_OFS  6
    #define KEY_CFG_PUFTRANS_PERM_MASK (1 << KEY_CFG_PUFTRANS_PERM_OFS)

/* MC (Monotonic Counter) */
#define ARMOR_MC_MAX_VAL          0x40000000
#define ARMOR_MC_NUM              4
#define ARMOR_MC_SIZE             4
#define ARMOR_MC_TOTAL_SIZE       (ARMOR_MC_SIZE * ARMOR_MC_NUM)
#define ARMOR_MC_MEM_ADDR         0x7FFA00

#define ARMOR_MC_CFG_NUM          ARMOR_MC_NUM
#define ARMOR_MC_CFG_SIZE         2
#define ARMOR_MC_CFG_TOTAL_SIZE   (ARMOR_MC_CFG_SIZE * ARMOR_MC_CFG_NUM)
#define ARMOR_MC_CFG_MEM_ADDR     0x7FF100

/* MC configuration */
#define MC_CFG_BYTE_0             0
    #define MC_CFG_NEED_MAC_OFS   0
    #define MC_CFG_NEED_MAC_MASK  (0x01 << MC_CFG_NEED_MAC_OFS)
    #define MC_CFG_INCR_PERM_OFS  1
    #define MC_CFG_INCR_PERM_MASK (0x01 << MC_CFG_INCR_PERM_OFS)
    /* CBC KEY */
    #define MC_CFG_MACID_OFS      2
    #define MC_CFG_MACID_MASK     (0x03 << MC_CFG_MACID_OFS)
#define MC_CFG_BYTE_1             1
    /* CTR KEY */
    /* IMAC is for MC Increment */
    #define MC_CFG_IMACID_OFS     0
    #define MC_CFG_IMACID_MASK   (0x03 << MC_CFG_IMACID_OFS)
    /* OMAC is for MC read */
    #define MC_CFG_OMACID_OFS     4
    #define MC_CFG_OMACID_MASK   (0x03 << MC_CFG_OMACID_OFS)

/* ArmorFlash Request Packet parameters */
#define ARMOR_MAC_SIZE          16
#define ARMOR_DATA_MAX_SIZE     32

/* IV related */
#define ARMOR_IV_SIZE           16
#define ARMOR_NONCE_SIZE        12
#define ARMOR_MACOUNT_SIZE      1
#define IV_TYPE_MAC_GEN         0
#define IV_TYPE_MAC             1
#define IV_TYPE_DATA            2

/* Vector related */
#define ARMOR_VECTOR1_SIZE      16
#define ARMOR_VECTOR2_SIZE      16
#define ARMOR_VECTOR_SIZE       (ARMOR_VECTOR1_SIZE + ARMOR_VECTOR2_SIZE)
#define ARMOR_VAR1_SIZE         3
#define ARMOR_VAR2_SIZE         2

/* Secure Packet read/write related */
#define ARMOR_PKT_ADDR          0x7FFE00
#define ARMOR_PKT_RESET_ADDR    0x7FFFE0

#define ARMOR_WR_SECURE_PKT_SIZE_WO_MAC_DATA (ARMOR_PKT_COUNT_SIZE + ARMOR_PKT_INST_SIZE + ARMOR_PKT_OP_SIZE + \
		ARMOR_PKT_VAR1_SIZE + ARMOR_PKT_VAR2_SIZE + ARMOR_PKT_CRC_SIZE)

/* secure field configuration memory */
typedef struct {
    union {
        uint8_t buf[SECUREFIELD_CFG_SIZE];
        struct {
            uint8_t sn[ARMOR_SN_SIZE];                                            /* [0x7FF007:0x7FF000] */
            uint8_t reserved0[8 * 7];                                             /* [0x7FF03F:0x7FF008] */
            uint8_t lock_reg[ARMOR_LKD_REG_TOTAL_SIZE];                           /* [0x7FF045:0x7FF040] */
            uint8_t reserved1[2 + 8 * 3 + 8 * 4];                                 /* [0x7FF07F:0x7FF046] */
            uint8_t data_config[ARMOR_DATAZONE_CFG_NUM][ARMOR_DATAZONE_CFG_SIZE]; /* [0x7FF0BF:0x7FF080] */
            uint8_t key_config[ARMOR_KEY_NUM][ARMOR_KEY_CFG_SIZE];                /* [0x7FF0CF:0x7FF0C0] */
            uint8_t reserved2[8 * 6];                                             /* [0x7FF0FF:0x7FF0D0] */
            uint8_t mc_config[ARMOR_MC_NUM][ARMOR_MC_CFG_SIZE];                   /* [0x7FF107:0x7FF100] */
            uint8_t reserved3[8 * 3];                                             /* [0x7FF11F:0x7FF108] */
            uint8_t spare[ARMOR_SPAREZONE_SIZE];                                  /* [0x7FF13F:0x7FF120] */
            uint8_t extra_zone[ARMOR_EXTRAZONE_SIZE];                             /* [0x7FF15F:0x7FF140] */
        };
    };
}securefield_config_memory_t;

/* information for armor security field */
typedef struct
{
	securefield_config_memory_t sf_config;  /* [0x7FF15F:0x7FF000] */
    uint8_t key[ARMOR_KEY_NUM][ARMOR_KEY_SIZE]; /* [0x7FF67F:0x7FF600] */
    uint8_t mc[ARMOR_MC_NUM][ARMOR_MC_SIZE];    /* [0x7FFA0F:0x7FFA00] */
} secure_flash_region_t;

/* information for mac calculation, Initialization Vector */
typedef union {
    uint8_t buf[ARMOR_IV_SIZE];
    struct {
        uint8_t flag;
        union {
        	uint8_t nonce_tot[ARMOR_NONCE_SIZE + ARMOR_MACOUNT_SIZE];
        	struct {
        		uint8_t nonce[ARMOR_NONCE_SIZE];
        		uint8_t macount;
        	};
        };
        uint8_t data_len[2];
        
    };
} armor_iv_t;

/* information for MAC calculation, Additional Authenticated Data */    
typedef union {
    uint8_t buf[ARMOR_VECTOR_SIZE];
    struct {
        /* Vector 1 */
        uint8_t reserved_len;
        uint8_t len;
        uint8_t reserved_mfr;
        uint8_t mfr_id;
        uint8_t armor_cmd;
        uint8_t op;
        uint8_t var1[ARMOR_VAR1_SIZE];
        uint8_t var2[ARMOR_VAR2_SIZE];
        uint8_t mac_status;
        uint8_t reserved_mc[ARMOR_MC_SIZE];
        /* Vector 2 & Data*/
        uint8_t linked_mc[ARMOR_MC_SIZE];
        uint8_t sn[ARMOR_SN_SIZE];
        uint8_t ex_zone_4b[4];
    };
} armor_vector_t;

typedef struct {
    secure_flash_region_t region;
    char const *rtn_err_msg;    
    uint8_t vector_len_tot;
    uint8_t ctr_key_id;
    uint8_t cbc_key_id;

    uint8_t linked_mc_id;
    uint8_t is_sf_mode;
    uint32_t is_sf_trng_en      :1, /* ArmorFlash RGEN enable */
	         is_nrandom_set     :1, /* NRANDOM bit is set to 1 in Key ConfigReg */
             is_omac_en         :1,
             is_imac_en         :1,
             is_nonce_valid     :1,
             is_nonce_from_host :1,
             is_imac_from_host  :1,
             verbose:1,
	         tb:1;
    union {
        uint8_t buf;
        struct {
            uint8_t is_inc_linked_mc :1,
                    is_inc_sn        :1,
                    is_inc_ext_zone  :1;
        };
    } op_mac_params;
} secure_flash_meta_t;

// const priv_provision_data_t priv_privision_data = {
//     .sf_config = {
//         .buf = {
//             0x34, 0x09, 0x21, 0x01, 0x10, 0x26, 0x1E, 0x14, /* 0x7FF000 - 0x7FF007 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF008 - 0x7FF00F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF010 - 0x7FF017 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF018 - 0x7FF01F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF020 - 0x7FF027 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF028 - 0x7FF02F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF030 - 0x7FF037 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF038 - 0x7FF03F */ 
//             0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF040 - 0x7FF047 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF048 - 0x7FF04F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF050 - 0x7FF057 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF058 - 0x7FF05F */ 
                                                                                    
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF060 - 0x7FF067 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF068 - 0x7FF06F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF070 - 0x7FF077 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF078 - 0x7FF07F */ 
//             0x2F, 0xC2, 0xA6, 0xFF, 0x2F, 0xC2, 0xA6, 0xFF, /* 0x7FF080 - 0x7FF087 */ 
//             0x2F, 0xC2, 0xA6, 0xFF, 0x2F, 0xC2, 0xA6, 0xFF, /* 0x7FF088 - 0x7FF08F */ 
//             0x2F, 0xC2, 0xA6, 0xFF, 0x2F, 0xC2, 0xA6, 0xFF, /* 0x7FF090 - 0x7FF097 */ 
//             0x2F, 0xC2, 0xA6, 0xFF, 0x2F, 0xC2, 0xA6, 0xFF, /* 0x7FF098 - 0x7FF09F */ 
//             0x3F, 0xC3, 0xE6, 0xFF, 0x3F, 0xC3, 0xE6, 0xFF, /* 0x7FF0A0 - 0x7FF0A7 */ 
//             0x3F, 0xC3, 0xE6, 0xFF, 0x3F, 0xC3, 0xE6, 0xFF, /* 0x7FF0A8 - 0x7FF0AF */ 
//             0x3F, 0xC3, 0xE6, 0xFF, 0x3F, 0xC3, 0xE6, 0xFF, /* 0x7FF0B0 - 0x7FF0B7 */ 
//             0x3F, 0xC3, 0xE6, 0xFF, 0x3F, 0x03, 0xEE, 0xFF, /* 0x7FF0B8 - 0x7FF0BF */ 
//             0x48, 0x00, 0x20, 0xEF, 0x48, 0x00, 0x20, 0xEF, /* 0x7FF0C0 - 0x7FF0C7 */ 
//             0x58, 0x11, 0x20, 0xEF, 0x58, 0x11, 0x20, 0xEF, /* 0x7FF0C8 - 0x7FF0CF */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0D0 - 0x7FF0D7 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0D8 - 0x7FF0DF */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0E0 - 0x7FF0E7 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0E8 - 0x7FF0EF */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0F0 - 0x7FF0F7 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF0F8 - 0x7FF0FF */ 
//             0x03, 0x00, 0x07, 0x11, 0x0B, 0x22, 0x0F, 0x33, /* 0x7FF100 - 0x7FF107 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF108 - 0x7FF10F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF110 - 0x7FF117 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF118 - 0x7FF11F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF120 - 0x7FF127 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF128 - 0x7FF12F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF130 - 0x7FF137 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF138 - 0x7FF13F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF140 - 0x7FF147 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF148 - 0x7FF14F */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x7FF150 - 0x7FF157 */ 
//             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  /* 0x7FF158 - 0x7FF15F */
//         }
//     },
//     .rot_pub_key = {
//         .length = 65,
//         .buf = {0x04, 0xc0, 0xd6, 0x38, 0x80, 0x3d, 0xbf, 0x10, 
//                 0x41, 0xad, 0x4f, 0xd2, 0x4c, 0xf5, 0xbd, 0x8b, 
//                 0x08, 0x64, 0x29, 0x10, 0x19, 0x9c, 0x59, 0xd7, 
//                 0x57, 0x18, 0x13, 0x75, 0x63, 0x53, 0x7a, 0xdf, 
//                 0xe0, 0x15, 0xf8, 0x35, 0x4f, 0xf9, 0x2f, 0x5b, 
//                 0xe7, 0x70, 0x5a, 0xe4, 0x9a, 0x42, 0xc7, 0xbf, 
//                 0xb4, 0x92, 0x63, 0xfc, 0x6c, 0x8b, 0x9d, 0xc4, 
//                 0x0e, 0x6c, 0xee, 0xe1, 0xbf, 0xdc, 0x9f, 0x0d, 0xe2
//         },
//     }

//     ,app_num = 2,
//     .app_meta[0] = {
//         .app_id = 1,
//         .data_zone_id = 1,
//         .pub_key = {0x04, 0xfe, 0x46, 0x2d, 0xfb, 0x29, 0xd0, 0xa3, 
//                     0xcc, 0x5a, 0xb3, 0x10, 0x5c, 0x2f, 0x24, 0xb7, 
//                     0xef, 0xa7, 0xe3, 0xed, 0x15, 0xb8, 0xa6, 0x38, 
//                     0x52, 0x24, 0x3b, 0xba, 0x1f, 0x3b, 0x55, 0xff, 
//                     0x03, 0x8e, 0x11, 0x5b, 0xcf, 0xb0, 0x9e, 0xbe, 
//                     0x03, 0xbc, 0x18, 0x08, 0xcd, 0x93, 0x30, 0xa1, 
//                     0x14, 0x01, 0x1d, 0x5c, 0xa8, 0x55, 0xf3, 0x17, 
//                     0xb2, 0x6e, 0x65, 0x1b, 0x01, 0x7a, 0x0a, 0x43, 0x16},
//     },
//     .app_meta[1] = {
//         .app_id = 2,
//         .data_zone_id = 2,
//         .pub_key = {0x04, 0x89, 0x4d, 0x59, 0xc4, 0x5c, 0x7d, 0x26, 
//                     0x2a, 0xaa, 0xa7, 0xba, 0xf8, 0xea, 0x22, 0xf5, 
//                     0x2c, 0x91, 0x2d, 0x0a, 0x3f, 0x32, 0xa4, 0x0a, 
//                     0x42, 0x6b, 0x36, 0xfe, 0x76, 0x06, 0xaa, 0xd5, 
//                     0x86, 0x5d, 0xf8, 0xde, 0x65, 0x64, 0x90, 0x2a, 
//                     0x16, 0xc5, 0x83, 0xe7, 0x5a, 0x4c, 0xd5, 0xaf, 
//                     0x25, 0x31, 0xee, 0x63, 0xc3, 0x36, 0xe4, 0xa5, 
//                     0x6a, 0x7e, 0x99, 0x9d, 0x7e, 0x65, 0x87, 0xc2, 0xa0},
//     }
//     .sinature = {},
// }
// #endif

#define MACRO_CIPHER_SUIITE                      \
    .number = 1;                                 \
	.cs[0] = {                                   \
		.key_exchange = CIPHER_SUITE_KEY_EX,     \
		.key_derive   = CIPHER_SUITE_KEY_DRV,    \
		.mac          = CIPHER_SUITE_KEY_MAC,    \
		.cipher       = CIPHER_SUITE_KEY_CIPHER, \
		.vendor0      = CIPHER_SUITE_VENDOR0,    \
	}

#define MACRO_ENCRTYPTION_REQUIREMENT                                 \
    .number = 4,                                                      \
    .encryption_req[CMDNAME_READ] = {                                 \
        .CmdNameEnum cmd_name = CMDNAME_READ,                         \
        .encryption           = ENC_AES_CCM_256,                      \
        .operation            = ENCOP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV, \
        .authen_by_device     = 0,                                    \
        .authen_by_host       = 1,				                      \
    },                                                                \
    .encryption_req[CMDNAME_PROGRAM] = {                              \
        .CmdNameEnum cmd_name = CMDNAME_PROGRAM,                      \
        .encryption           = ENC_AES_CCM_256,                      \
        .operation            = ENCOP_ENCRYPT_TAG_DATA_ENC_IV,        \
        .authen_by_device     = 1,                                    \
        .authen_by_host       = 0,                                    \
    },                                                                \
    .encryption_req[CMDNAME_ERASE] = {                                \
        .CmdNameEnum cmd_name = CMDNAME_ERASE,                        \
        .encryption           = ENC_AES_CCM_256,                      \
        .operation            = ENCOP_ENCRYPT_TAG_DATA_ENC_IV,        \
        .authen_by_device     = 1,                                    \
        .authen_by_host       = 0,				                      \
    },                                                                \
    .encryption_req[CMDNAME_RD_PUF] = {                               \
        .CmdNameEnum cmd_name = CMDNAME_RD_PUF,                       \
        .encryption           = ENC_AES_CCM_256,                      \
        .operation            = ENCOP_AUTHEN_TAG_DECRYPT_DATA_ENC_IV, \
        .authen_by_device     = 0,                                    \
        .authen_by_host       = 1,				                      \
    }


#endif
