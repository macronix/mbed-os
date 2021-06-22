#ifndef MBED_MACRONIX_COMMON_ARMORFLASH_H
#define MBED_MACRONIX_COMMON_ARMORFLASH_H

#include <stdint.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* Standard Flash commands */
#define STD_INST_RDSCUR          0x2B
#define STD_INST_RDCR            0x15
#define STD_INST_RDSR            0x05
#define STD_INST_RDID            0x9F
#define STD_INST_RSTEN           0x66
#define STD_INST_RST             0x99
#define STD_INST_WREN            0x06
#define STD_INST_SECURE_READ     0x03
#define STD_INST_SECURE_WRITE    0x02
#define STD_INST_SECURE_READ_4B  0x13
#define STD_INST_SECURE_WRITE_4B 0x12
#define STD_INST_PP              0x02
#define STD_INST_READ            0x03
#define STD_INST_ERASE_4K        0x20
#define STD_INST_PP_4B           0x12
#define STD_INST_READ_4B         0x13
#define STD_INST_ERASE_4K_4B     0x21
#define STD_INST_FREAD           0x0B
#define STD_INST_ENSF            0xB2
#define STD_INST_EXSF            0xC2
#define STD_INST_EN4B            0xB7

/* Status register definition for Normal Field */
typedef enum {
    SR_BIT_WIP        = (1<<0), /* device is ready */
    SR_BIT_WEL        = (1<<1), /* write enable */
    SR_BIT_QE         = (1<<6), /* quad enable */
    SR_BIT_SRWD       = (1<<7), /* status register write protect */
}StatusRegEnum;

/* security register definition for Normal Field */
typedef enum {
    SCUR_BIT_SCUR_OPT = (1<<0), /* factory lock */
    SCUR_BIT_LDSO     = (1<<1), /* indicate if security OTP is locked down */
    SCUR_BIT_PSB      = (1<<2), /* program suspend bit */
    SCUR_BIT_ESB      = (1<<3), /* erase suspend bit   */
    SCUR_BIT_ENSF     = (1<<4), /* enter the security field or not */
    SCUR_BIT_PFB      = (1<<5), /* program failed bit   */
    SCUR_BIT_EFB      = (1<<6), /* erase failed bit   */
}SecurityRegEnum;

/* Conficuration register definition for Normal Field */
typedef enum {
    CR_BIT_TB         = (1<<3), /* top/bottom select */
	CR_BIT_4BEN       = (1<<5), /* 4-byte/3-byte address mode */
	CR_BIT_DC0        = (1<<6), /* dummy cycle 0 */
	CR_BIT_DC1        = (1<<7), /* dummy cycle 1 */
}ConfigurationRegEnum;

/* status register definition for Security Field */
typedef enum {
    SF_SR_BIT_WIP          = (1<<0), /* device is ready */
    SF_SR_BIT_WEL          = (1<<1), /* write enable */
    SF_SR_BIT_CRC_ERR      = (1<<5), /* CRC is incorrect in most recent command */
    SF_SR_BIT_OUT_RDY      = (1<<6), /* the PacketOut is ready to read */
    SF_SR_BIT_ERR          = (1<<7), /* an error code in most recent command */
}SecureFieldStatusRegEnum;

/* Armor Return Status */
typedef enum
{
    ARMOR_RTN_OPERATION_SUCCESS = 0x00,
    ARMOR_RTN_CMD_ERR           = 0x01,
    ARMOR_RTN_ADDR_ERR          = 0x02,
    ARMOR_RTN_BOUNDARY_ERR      = 0x04,
    ARMOR_RTN_PERM_ERR          = 0x08,
    ARMOR_RTN_NONCE_ERR         = 0x10,
    ARMOR_RTN_MAC_ERR           = 0x20,
    ARMOR_RTN_CNT_ERR           = 0x40,
    ARMOR_RTN_KEY_ERR           = 0x80,
    ARMOR_RTN_LKD_ERR           = 0xA0,
    ARMOR_RTN_VFY_ERR           = 0xC0
} ArmorRtnMsgEnum;

#endif
