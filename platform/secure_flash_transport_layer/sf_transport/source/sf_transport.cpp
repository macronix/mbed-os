#include "sf_transport.h"
#include "mbed_trace.h"
#include <string.h>

//typedef enum {
//	FM_1S_1S_1S, //(SPI  Mode) READ, FREAD
//	FM_1S_1S_2S, //(DSPI Mode) DREAD
//	FM_1S_2S_2S, //(DPI  Mode) 2READ
//	FM_1S_1S_4S, //(QSPI Mode) QREAD
//	FM_1S_4S_4S, //(QPI  Mode) 4READ
//
//}FlashModeEnum;

/* default SPI flash protocol */
#define SPI_CMD_SIZE     1
#define SPI_CMD_BITS     1
#define SPI_CMD_DRD      0
#define SPI_ADDR_SIZE    3
#define SPI_ADDR_BITS    1
#define SPI_ADDR_DRD     0
#define SPI_DUMMY_VAL    0
#define SPI_DUMMY_BYTES 0
#define SPI_DATA_BITS    1
#define SPI_DATA_DRD     0

static const flash_protocol_t spi_protocol = {
	.inst_len     = SPI_CMD_SIZE,
	.inst_bits    = SPI_CMD_BITS,

	.addr_len     = SPI_ADDR_SIZE,
	.addr_bits    = SPI_ADDR_BITS,

	.dummy_val    = SPI_DUMMY_VAL,
	.dummy_bytes = SPI_DUMMY_BYTES,

	.data_bits    = SPI_DATA_BITS,

	.inst_drd     = SPI_CMD_DRD,
	.addr_drd     = SPI_ADDR_DRD,
	.data_drd     = SPI_DATA_DRD,
};

SecureFlashTransport::SecureFlashTransport(SECURE_FLASH_TYPE *flash, int freq)
    : _flash(flash), _freq(freq)
{
}
int SecureFlashTransport::init()
{
	set_frequency(_freq);
	memcpy(&flash_protocol, &spi_protocol, sizeof(flash_protocol));
    memset(&secure_packet, 0, sizeof(secure_packet));
    return 0;
}

int SecureFlashTransport::deinit()
{
    return 0;
}

int SecureFlashTransport::read_secure_packet(uint64_t inst, uint8_t inst_len, 
        uint64_t address, uint8_t address_len, uint8_t dummy_bytes, 
        uint8_t *packet, uint64_t size)
{
    if(0 != send_general_command(inst, inst_len, address, address_len, dummy_bytes, NULL, 0, packet, size)) {    
        tr_error("read secure packet failed");
        return -1;
    }	
    return 0;
}

int SecureFlashTransport::write_secure_packet(uint64_t inst, uint8_t inst_len, 
        uint64_t address, uint8_t address_len, 
        const uint8_t *data, uint64_t size)
{	
    if(0 != send_general_command(inst, inst_len, address, 0, 0, data, size, NULL, 0)) {    
        tr_error("write secure packet failed");
        return -1;
    }
    
    return 0;
}

int SecureFlashTransport::wrie_rpmc_packet(int inst, const uint8_t *data, uint8_t size)
{
    if(0 != send_general_command(inst, 1, 0, 0, 0, data, size, NULL, 0)) {    
        tr_error("writ RPMC Packet failed");
        return -1;
    }
    return 0
}

int SecureFlashTransport::read_rpmc_packet(int inst, uint64_t dummy_byte, uint8_t *data, uint8_t size)
{
    status = send_general_command(inst, 1, 0, 0, dummy_byte, NULL, 0, data, size);
    if (0 != status) {
        tr_error("writ RPMC Packet failed");
        return -1;
    }
    return 0
            
}

#if defined(DEVICE_SPI)
void SecureFlashTransport::set_frequency(int freq)
{
	tr_debug("Set clock from SPI host controller to %d Hz\n", freq);
    _flash->frequency(freq);
    _freq = freq;
}

int SecureFlashTransport::send_general_command(uint64_t inst, uint8_t inst_len,
        uint64_t addr, uint8_t addr_len,
	    uint8_t dummy_byte,
        const uint8_t *tx_buf, uint64_t tx_len,
        uint8_t *rx_buf, uint64_t rx_len)
{
	const char *tx_data = reinterpret_cast<const char*>(tx_buf);
	char *rx_data = reinterpret_cast<char*>(rx_buf);
	tr_debug("General Inst: 0x%xh, addr: %llu, tx size: %llu, rx size: %llu\n", inst, addr, tx_len, rx_len);
    // Send a general command Instruction to driver

    _flash->select();

    // Write Instruction
    for (inst_len) {
        for (int inst_shift = ((inst_len - 1) * 8); inst_shift >= 0; inst_shift -=8) {
            _flash->write((inst > inst_shift) & 0xFF);
        }
    }
    
    // Write Address
    if (addr_len) {        
        for (int addr_shift = ((addr_len - 1) * 8); addr_shift >= 0; addr_shift -= 8) {
            _flash->write((addr >> addr_shift) & 0xFF);
        }        
    }
    // Write Dummy Cycles Bytes
    
    for (uint32_t i = 0; i < dummy_byte; i++) {
        _flash->write(flash_protocol.dummy_val);
    }
    

    // Read/Write Data
    _flash->write(tx_data, (int)tx_len, rx_data, (int)rx_len);

    _flash->deselect();

    return 0;
}

int SecureFlashTransport::send_read_command(int read_inst, uint64_t addr, uint8_t *rx_buf, uint64_t size)
{
	tr_debug("Read Inst: %xh, addr: %" PRIx64  "h, size: %" PRIx64  "h\r\n", read_inst, addr, size);
    _flash->select();

    // Write 1 byte Instruction
    _flash->write(read_inst);

    // Write Address (can be either 3 or 4 bytes long)
    for (int address_shift = ((flash_protocol.addr_len - 1) * 8); address_shift >= 0; address_shift -= 8) {
        _flash->write((addr >> address_shift) & 0xFF);
    }

    // Write Dummy Cycles Bytes
    for (uint32_t i = 0; i < flash_protocol.dummy_bytes; i++) {
        _flash->write(flash_protocol.dummy_val);
    }

    // Read Data
    for (uint64_t i = 0; i < size; i++) {
    	rx_buf[i] = _flash->write(0);
    }

    _flash->deselect();

    return 0;
}

int SecureFlashTransport::send_program_command(int prog_inst, uint64_t addr, const uint8_t *tx_buf, uint64_t size)
{
    // Send Program (write) command to device driver
	tr_debug("Program Inst: %xh, addr: %" PRIx64  "h, size: %" PRIx64  "h\r\n", prog_inst, addr, size);
    _flash->select();

    // Write 1 byte Instruction
    _flash->write(prog_inst);

    // Write Address (can be either 3 or 4 bytes long)
    for (int address_shift = ((flash_protocol.addr_len - 1) * 8); address_shift >= 0; address_shift -= 8) {
        _flash->write((addr >> address_shift) & 0xFF);
    }

    // Write Data
    for (uint64_t i = 0; i < size; i++) {
        _flash->write(tx_buf[i]);
    }

    _flash->deselect();

    return 0;
}

int SecureFlashTransport::send_erase_command(int erase_inst, uint64_t addr, uint64_t size)
{
	tr_debug("Erase Inst: 0x%xh, addr: %llu, size: %llu", erase_inst, addr, size);
    addr = (((int)addr) & 0xFFFFF000);
    send_general_command(erase_inst, addr, flash_protocol.addr_len, 0, NULL, 0, NULL, 0);
    return 0;

}
#endif
