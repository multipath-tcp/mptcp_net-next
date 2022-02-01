/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * CEC driver for SECO MEC-based Boards
 *
 * Author:  Ettore Chimenti <ek5.chimenti@gmail.com>
 * Copyright (C) 2022, SECO SpA.
 */

/* MailBox definitions */
#define MBX_RESERVED_SIZE	0x10
#define MBX_RESERVED_BASE	0x2b0

#define BAR_FROM_MBX_BASE(x)	(x + MBX_RESERVED_BASE)

#define RES_BAR_OFFSET		0
#define BSY_BAR_OFFSET		4
#define MBX_BAR_OFFSET		0xc

#define MBX_RESOURCE_REGISTER	BAR_FROM_MBX_BASE(RES_BAR_OFFSET)
#define MBX_BUSY_REGISTER	BAR_FROM_MBX_BASE(BSY_BAR_OFFSET)
#define MBX_ACCESS_BAR		BAR_FROM_MBX_BASE(MBX_BAR_OFFSET)

#define EC_REGISTER_INDEX	MBX_ACCESS_BAR
#define EC_REGISTER_DATA	(EC_REGISTER_INDEX + 1)
#define EC_MBX_SIZE		0x20

#define EC_COMMAND_REGISTER	0
#define EC_RESULT_REGISTER	1
#define EC_STATUS_REGISTER	2
#define EC_MBX_REGISTER		0x10

#define EC_CMD_TIMEOUT		0x30000 /* Maximum wait loop */

/* Firmware version data struct and definitions */
#define FIRMWARE_TIME_STAMP_SIZE (EC_MBX_SIZE - sizeof(u32))

struct version_t {
	u8 minor;
	u8 major;
};

struct version_msg_t {
	struct version_t fw;
	struct version_t lib;
	u8 firmware_ts[FIRMWARE_TIME_STAMP_SIZE];
};

/* CEC data structs and constant definitions */
#define MECCEC_MAX_MSG_SIZE 16

struct seco_meccec_msg_t {
	u8 bus;
	u8 send;
	u8 dest;
	u8 data[MECCEC_MAX_MSG_SIZE];
	u8 size;
};

struct seco_meccec_logaddr_t {
	u8 bus;
	u8 addr;
};

struct seco_meccec_phyaddr_t {
	u16 bus;
	u16 addr;
};

struct seco_meccec_status_t {
	u8 status_ch0;
	u8 status_ch1;
	u8 status_ch2;
	u8 status_ch3;
};

/* Status data */
#define SECOCEC_STATUS_MSG_RECEIVED_MASK	BIT(0)
#define SECOCEC_STATUS_RX_ERROR_MASK		BIT(1)
#define SECOCEC_STATUS_MSG_SENT_MASK		BIT(2)
#define SECOCEC_STATUS_TX_ERROR_MASK		BIT(3)

#define SECOCEC_STATUS_TX_NACK_ERROR		BIT(4)
#define SECOCEC_STATUS_RX_OVERFLOW_MASK		BIT(5)

/* MBX Status bitmap values from EC to Host */
enum MBX_STATUS {
	MBX_OFF     = 0,	/* Disable MBX Interface */
	MBX_ON      = 1,	/* Enable MBX Interface  */
	MBX_ACTIVE0 = (1 << 6),	/* MBX AGENT 0 active    */
	MBX_QUEUED0 = (1 << 7),	/* MBX AGENT 0 idle      */
};

#define AGENT_IDLE(x)      0
#define AGENT_QUEUED(x)    (MBX_QUEUED0 >> (2 * x))
#define AGENT_ACTIVE(x)    (MBX_ACTIVE0 >> (2 * x))
#define AGENT_MASK(x)      (AGENT_QUEUED(x) + AGENT_ACTIVE(x))
#define AGENT_DONE(x)      AGENT_MASK(x)
#define MBX_STATUS_DEFAULT 0

/* MBX user IDs */
enum AGENT_IDS {
	AGENT_BIOS, /* BIOS AGENT */
	AGENT_ACPI, /* ACPI AGENT */
	AGENT_EAPI, /* EAPI AGENT */
	AGENT_USER, /* USER AGENT */
	AGENT_NONE, /* No AGENT   */
};

/* MBX command results */
enum CMD_RESULT {
	EC_NO_ERROR = 0,		/* Success	    */
	EC_UNKNOWN_COMMAND_ERROR,	/* Unknown command  */
	EC_INVALID_ARGUMENT_ERROR,	/* Invalid argument */
	EC_TIMEOUT_ERROR,		/* Waiting Time-out */
	EC_DEVICE_ERROR,		/* Device error     */
};

/* MBX commands */
enum MBX_CMDS {
	GET_FIRMWARE_VERSION_CMD = 0,    /* Get firmware version record		*/
	CEC_WRITE_CMD		 = 0x80, /* Write CEC command			*/
	CEC_READ_CMD		 = 0x81, /* Read CEC command			*/
	GET_CEC_STATUS_CMD	 = 0x82, /* Get CEC status regisers		*/
	SET_CEC_LOGADDR_CMD	 = 0x83, /* Set CEC Logical Address		*/
	SET_CEC_PHYADDR_CMD	 = 0x84, /* Set CEC Physical Address		*/
	REQUEST_MBX_ACCESS_CMD   = 0xf0, /* First request access command	*/
	RELEASE_MBX_ACCESS_CMD   = 0xf8, /* First release access command	*/
};

#define REQUEST_MBX_ACCESS(x) (REQUEST_MBX_ACCESS_CMD + x)
#define RELEASE_MBX_ACCESS(x) (RELEASE_MBX_ACCESS_CMD + x)
