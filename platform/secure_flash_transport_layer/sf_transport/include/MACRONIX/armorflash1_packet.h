#ifndef MBED_ARMORFLASH1_PACKET_H
#define MBED_ARMORFLASH1_PACKET_H

#if defined(TARGET_MX75L25690F)
	#define ARMOR_PKT_COUNT_SIZE    1
	#define ARMOR_PKT_INST_SIZE     1
	#define ARMOR_PKT_OP_SIZE       1
	#define ARMOR_PKT_VAR1_SIZE     3
	#define ARMOR_PKT_VAR2_SIZE     2
	#define ARMOR_PKT_MAC_SIZE      16
	#define ARMOR_PKT_DATA_MAX_SIZE 32
	#define ARMOR_PKT_CRC_SIZE      2
	#define ARMOR_PKT_RTN_CODE_SIZE 1
	/* ArmorFlash Request Packet (for secure packet read/write) */
	typedef struct
	{
		uint8_t count;
		uint8_t inst;
		uint8_t op;
		uint8_t var1[ARMOR_PKT_VAR1_SIZE];
		uint8_t var2[ARMOR_PKT_VAR2_SIZE];
		uint8_t mac_data_crc[ARMOR_PKT_MAC_SIZE + ARMOR_PKT_DATA_MAX_SIZE + ARMOR_PKT_CRC_SIZE];
	} secure_packet_write_t;

	/* ArmorFlash Response Packet */
	typedef struct
	{
		uint8_t count;
		uint8_t return_code;
		uint8_t mac_data_crc[ARMOR_PKT_MAC_SIZE + ARMOR_PKT_DATA_MAX_SIZE + ARMOR_PKT_CRC_SIZE];
	} secure_read_packet_t;	
#endif