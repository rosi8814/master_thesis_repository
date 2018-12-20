/******************************************************************************/
/**
 * @file
 * @brief MAC HW block for RC4
 *
 ******************************************************************************/
/*
 *  Copyright (c) Catena Holding BV. 2017-2018
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include <iostream>
#include <string.h>
#include <stdint.h>
#include "catFwTarget.h"
#include "catFwDebug.h"
#include "catFwMac80211Status.h"
#include "catFwMac80211Standard.h"
#include "catFwMac80211Utils.h"
#include "catHwMacCrypterRc4.hpp"
#include "catHwMacRequests.hpp"
#include "catHwMacIrqEvents.hpp"


/*******************************************************************************
 *  DEFINES
 ******************************************************************************/

/*******************************************************************************
 *  OBJECTS
 ******************************************************************************/

CatHwMacCrypterRc4::CatHwMacCrypterRc4() {

    std::cout << "Creating Crypto RC4 HW object" << std::endl;
}

CatHwMacCrypterRc4::~CatHwMacCrypterRc4() {
}


/*******************************************************************************
 *  FUNCTIONS
 ******************************************************************************/

/**
 * @brief Set the current RC4 key
 *
 * @param key_p RC4 key
 * @param len Length of RC4 key in bytes
 * @return Status of the key setting
 */
catFwMac80211_statusCode_t CatHwMacCrypterRc4::cryptoRc4SetKey(
        const uint8_t *const key_p,
        const uint16_t keyLenOctets) {

    if (keyLenOctets > maxSupportedRc4KeyLength) {
        return MAC80211_STATUS_CODE_INVALID_PARAMETERS_e;
    }

    this->key_p = key_p;
    this->keyLenOctets = keyLenOctets;

    return MAC80211_STATUS_CODE_SUCCESS_e;
}

void CatHwMacCrypterRc4::cryptoRc4ResetKey(void) {

    this->key_p = NULL;
    this->keyLenOctets = 0;
}

/**
 * @brief Request the calculation of an RC4 stream cipher based on the given input
 *
 * The Actual crypto operation will not be performed here, but rather a command flag
 * is set and the required parameters are stored for later processing.
 *
 * The operation requires a valid set RC4 key and key length
 *
 * The input is already XORed with the RC4 cipher, so the output contains the
 * final cipher stream. If the XOR shall not be done (as in the RFC6229 test vectors),
 * the data vector shall contain only zero octets.
 *
 * The size of the output buffer needs to be (at least) the same as the input buffer.
 *
 * @param[in] inputBuffer_p Pointer to array that contains the input data to be processed using RC4
 * @param[in] dataLenOctets Length of data in bytes to be encrypted
 * @param[out] outputBuffer_p Pointer to array that contains the ourput data that has been processed using RC4
 */
void CatHwMacCrypterRc4::cryptoRc4Request(
        const uint8_t *const inputBuffer_p,
        const uint16_t dataLenOctets,
        uint8_t *const outputBuffer_p) {

    // Store data for later processing
    this->inputBuffer_p = inputBuffer_p;
    this->dataLenOctets = dataLenOctets;
    this->outputBuffer_p = outputBuffer_p;

    // Enqueue new HW Event in order to run the actual crypto procedure later
    catHwMacFwRequests.queueRequestToHw(REQ_MACFW_CRYPTO_RC4_e);
}

/**
 * @brief Execute the previously requested calculation of an RC4 stream cipher based on the stored input
 */
void CatHwMacCrypterRc4::cryptoRc4Execute(void) {

    uint32_t i, j, k;
    uint8_t S[256], *pos;
    uint32_t kpos;

    // Copy input buffer to output buffer, since the RC4 algorithm completely works on the output buffer
    memmove(outputBuffer_p, inputBuffer_p, dataLenOctets);

    /* Setup RC4 state */
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    j = 0;
    kpos = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key_p[kpos]) & 0xff;
        kpos++;
        if (kpos >= keyLenOctets) {
            kpos = 0;
        }
        SWAP_UINT8(&S[i], &S[j]);
    }

    i = j = 0;
    /* Apply RC4 to data */
    pos = outputBuffer_p;
    for (k = 0; k < dataLenOctets; k++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        SWAP_UINT8(&S[i], &S[j]);
        *pos++ ^= S[(S[i] + S[j]) & 0xff];
    }

    // After finalizing RC4 notify SW via Event
    catHwMacIrqEvents.queueNewEvent(MAC_IRQ_CRYPTO_RC4_e, MAC_IRQ_CRYPTO_RC4_DELAY_US);
}
