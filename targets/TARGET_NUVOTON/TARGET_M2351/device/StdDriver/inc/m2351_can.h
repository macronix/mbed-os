/**************************************************************************//**
 * @file     can.h
 * @version  V1.00
 * @brief    M2351 Series CAN Driver Header File
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * @copyright (C) 2016 Nuvoton Technology Corp. All rights reserved.
 *
 ******************************************************************************/
#ifndef __CAN_H__
#define __CAN_H__


#ifdef __cplusplus
extern "C"
{
#endif


/** @addtogroup Standard_Driver Standard Driver
  @{
*/

/** @addtogroup CAN_Driver CAN Driver
  @{
*/

/** @addtogroup CAN_EXPORTED_CONSTANTS CAN Exported Constants
  @{
*/
/*---------------------------------------------------------------------------------------------------------*/
/* CAN Test Mode Constant Definitions                                                                      */
/*---------------------------------------------------------------------------------------------------------*/
#define    CAN_NORMAL_MODE   0U    /*!< CAN select normal mode */
#define    CAN_BASIC_MODE    1U    /*!< CAN select basic mode */

/*---------------------------------------------------------------------------------------------------------*/
/* Message ID Type Constant Definitions                                                                    */
/*---------------------------------------------------------------------------------------------------------*/
#define    CAN_STD_ID    0UL    /*!< CAN select standard ID */
#define    CAN_EXT_ID    1UL    /*!< CAN select extended ID */

/*---------------------------------------------------------------------------------------------------------*/
/* Message Frame Type Constant Definitions                                                                 */
/*---------------------------------------------------------------------------------------------------------*/
#define    CAN_REMOTE_FRAME    0    /*!< CAN frame select remote frame */
#define    CAN_DATA_FRAME    1      /*!< CAN frame select data frame */

/*@}*/ /* end of group CAN_EXPORTED_CONSTANTS */


/** @addtogroup CAN_EXPORTED_STRUCTS CAN Exported Structs
  @{
*/
/**
  * @details    CAN message structure
  */
typedef struct
{
    uint32_t  IdType;       /*!< ID type */
    uint32_t  FrameType;    /*!< Frame type */
    uint32_t  Id;           /*!< Message ID */
    uint8_t   DLC;          /*!< Data length */
    uint8_t   Data[8];      /*!< Data */
} STR_CANMSG_T;

/**
  * @details    CAN mask message structure
  */
typedef struct
{
    uint8_t   u8Xtd;      /*!< Extended ID */
    uint8_t   u8Dir;      /*!< Direction */
    uint32_t  u32Id;      /*!< Message ID */
    uint8_t   u8IdType;   /*!< ID type*/
} STR_CANMASK_T;

/*@}*/ /* end of group CAN_EXPORTED_STRUCTS */

/** @cond HIDDEN_SYMBOLS */
#define MSG(id)  (id)
/** @endcond HIDDEN_SYMBOLS */

/** @addtogroup CAN_EXPORTED_FUNCTIONS CAN Exported Functions
  @{
*/

/**
 * @brief Get interrupt status.
 *
 * @param[in] can The base address of can module.
 *
 * @return CAN module status register value.
 *
 * @details Status Interrupt is generated by bits BOff (CAN_STATUS[7]), EWarn (CAN_STATUS[6]),
 *          EPass (CAN_STATUS[5]), RxOk (CAN_STATUS[4]), TxOk (CAN_STATUS[3]), and LEC (CAN_STATUS[2:0]).
 */
#define CAN_GET_INT_STATUS(can) ((can)->STATUS)

/**
 * @brief Get specified interrupt pending status.
 *
 * @param[in] can The base address of can module.
 *
 * @return The source of the interrupt.
 *
 * @details If several interrupts are pending, the CAN Interrupt Register will point to the pending interrupt
 *          with the highest priority, disregarding their chronological order.
 */
#define CAN_GET_INT_PENDING_STATUS(can) ((can)->IIDR)

/**
 * @brief Disable wake-up function.
 *
 * @param[in] can The base address of can module.
 *
 * @return None
 *
 * @details  The macro is used to disable wake-up function.
 */
#define CAN_DISABLE_WAKEUP(can) ((can)->WU_EN = 0)

/**
 * @brief Enable wake-up function.
 *
 * @param[in] can The base address of can module.
 *
 * @return None
 *
 * @details User can wake-up system when there is a falling edge in the CAN_Rx pin.
 */
#define CAN_ENABLE_WAKEUP(can) ((can)->WU_EN = CAN_WU_EN_WAKUP_EN_Msk)

/**
 * @brief Get specified Message Object new data into bit value.
 *
 * @param[in] can The base address of can module.
 * @param[in] u32MsgNum Specified Message Object number, valid value are from 0 to 31.
 *
 * @return Specified Message Object new data into bit value.
 *
 * @details The NewDat bit (CAN_IFn_MCON[15]) of a specific Message Object can be set/reset by the software through the IFn Message Interface Registers
 *          or by the Message Handler after reception of a Data Frame or after a successful transmission.
 */
#define CAN_GET_NEW_DATA_IN_BIT(can, u32MsgNum) ((u32MsgNum) < 16 ? (can)->NDAT1 & (1 << (u32MsgNum)) : (can)->NDAT2 & (1 << ((u32MsgNum)-16)))


/*---------------------------------------------------------------------------------------------------------*/
/* Define CAN functions prototype                                                                          */
/*---------------------------------------------------------------------------------------------------------*/
uint32_t CAN_SetBaudRate(CAN_T *tCAN, uint32_t u32BaudRate);
void CAN_Close(CAN_T *tCAN);
uint32_t CAN_Open(CAN_T *tCAN, uint32_t u32BaudRate, uint32_t u32Mode);
void CAN_CLR_INT_PENDING_BIT(CAN_T *tCAN, uint8_t u32MsgNum);
void CAN_EnableInt(CAN_T *tCAN, uint32_t u32Mask);
void CAN_DisableInt(CAN_T *tCAN, uint32_t u32Mask);
int32_t CAN_Transmit(CAN_T *tCAN, uint32_t u32MsgNum, STR_CANMSG_T* pCanMsg);
int32_t CAN_Receive(CAN_T *tCAN, uint32_t u32MsgNum, STR_CANMSG_T* pCanMsg);
int32_t CAN_SetMultiRxMsg(CAN_T *tCAN, uint32_t u32MsgNum, uint32_t u32MsgCount, uint32_t u32IDType, uint32_t u32ID);
int32_t CAN_SetRxMsg(CAN_T *tCAN, uint32_t u32MsgNum, uint32_t u32IDType, uint32_t u32ID);
int32_t CAN_SetRxMsgAndMsk(CAN_T *tCAN, uint32_t u32MsgNum, uint32_t u32IDType, uint32_t u32ID, uint32_t u32IDMask);
int32_t CAN_SetTxMsg(CAN_T *tCAN, uint32_t u32MsgNum, STR_CANMSG_T* pCanMsg);
int32_t CAN_TriggerTxMsg(CAN_T  *tCAN, uint32_t u32MsgNum);
void CAN_EnterInitMode(CAN_T *tCAN, uint8_t u8Mask);
void CAN_LeaveInitMode(CAN_T *tCAN);
void CAN_WaitMsg(CAN_T *tCAN);
uint32_t CAN_GetCANBitRate(CAN_T *tCAN);
void CAN_EnterTestMode(CAN_T *tCAN, uint8_t u8TestMask);
void CAN_LeaveTestMode(CAN_T *tCAN);
uint32_t CAN_IsNewDataReceived(CAN_T *tCAN, uint8_t u8MsgObj);
int32_t CAN_BasicSendMsg(CAN_T *tCAN, STR_CANMSG_T* pCanMsg);
int32_t CAN_BasicReceiveMsg(CAN_T *tCAN, STR_CANMSG_T* pCanMsg);
int32_t CAN_SetRxMsgObjAndMsk(CAN_T *tCAN, uint8_t u8MsgObj, uint8_t u8idType, uint32_t u32id, uint32_t u32idmask, uint8_t u8singleOrFifoLast);
int32_t CAN_SetRxMsgObj(CAN_T *tCAN, uint8_t u8MsgObj, uint8_t u8idType, uint32_t u32id, uint8_t u8singleOrFifoLast);
int32_t CAN_ReadMsgObj(CAN_T *tCAN, uint8_t u8MsgObj, uint8_t u8Release, STR_CANMSG_T* pCanMsg);


/*@}*/ /* end of group CAN_EXPORTED_FUNCTIONS */

/*@}*/ /* end of group CAN_Driver */

/*@}*/ /* end of group Standard_Driver */

#ifdef __cplusplus
}
#endif

#endif /* __CAN_H__ */

/*** (C) COPYRIGHT 2016 Nuvoton Technology Corp. ***/
