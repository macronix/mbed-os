#ifndef MBED_SF_TRANSPORT_H
#define MBED_SF_TRANSPORT_H

#include "drivers/DigitalOut.h"
#include "sf_transport_config.h"

#if defined(DEVICE_SPI)
#include "drivers/SPI.h"
	#define SECURE_FLASH_TYPE mbed::SPI
#elif defined(DEVICE_QSPI)
#include "drivers/QSPI.h"
	#define SECURE_FLASH_TYPE mbed::QSPI
#elif defined(DEVICE_OSPI)
#include "drivers/OSPI.h"
	#define SECURE_FLASH_TYPE mbed::OSPI
#endif

typedef struct {
	uint8_t inst_len;
	uint8_t inst_bits;

	uint8_t addr_len;
	uint8_t addr_bits;

	uint8_t dummy_val;
	uint8_t dummy_bytes;

	uint8_t data_bits;

	uint8_t inst_drd:1,
			addr_drd:1,
			data_drd:1;
}flash_protocol_t;

class SecureFlashTransport {
public:	
	flash_protocol_t flash_protocol;

	SecureFlashTransport(SECURE_FLASH_TYPE *flash, int freq);

	int init();
	int deinit();

	int read_secure_packet(int command, uint64_t address, uint8_t latency_cycles, uint8_t *packet, uint64_t size);
	int write_secure_packet(int command, uint64_t address, const uint8_t *packet, uint64_t size);

	int wrie_rpmc_packet(int inst, uint8_t *data, uint8_t size);
	int read_rpmc_packet(int inst, uint64_t dummy_cycles, uint8_t *data, uint8_t size);

	void set_frequency(int freq);
	int send_general_command(uint64_t inst, uint8_t inst_len, 
			uint64_t addr, uint8_t addr_len, uint8_t dummy_len, 
			const uint8_t *tx_buf, uint64_t tx_len, uint8_t *rx_buf, uint64_t rx_len);
	int send_read_command(int read_inst, uint64_t addr, uint8_t *buffer, uint64_t size);
	int send_program_command(int prog_inst, uint64_t addr, const uint8_t *buffer, uint64_t size);
	int send_erase_command(int erase_inst, uint64_t addr, uint64_t size);	

private:
	SECURE_FLASH_TYPE *_flash;
	int _freq;
};
#endif
