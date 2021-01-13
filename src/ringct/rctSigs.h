// Copyright (c) 2016, Monero Research Labs
//
// Author: Shen Noether <shen.noether@gmx.com>
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

//#define DBG

#ifndef RCTSIGS_H
#define RCTSIGS_H

#include <cstddef>
#include <vector>
#include <tuple>

#include "crypto/generic-ops.h"

extern "C"
{
#include "crypto/random.h"
#include "crypto/keccak.h"
}
#include "crypto/crypto.h"

#include "rctTypes.h"
#include "rctOps.h"

//Define this flag when debugging to get additional info on the console
#ifdef DBG
#define DP(x) dp(x)
#else
#define DP(x)
#endif

namespace hw
{
    class device;
}

namespace rct
{

    clsag CLSAG_Gen(const key &message, const keyV &P, const key &p, const keyV &C, const key &z, const keyV &C_nonzero, const key &C_offset, const unsigned int l, const multisig_kLRki *kLRki, key *mscout, key *mspout, hw::device &hwdev);
    clsag CLSAG_Gen(const key &message, const keyV &P, const key &p, const keyV &C, const key &z, const keyV &C_nonzero, const key &C_offset, const unsigned int l);
    clsag proveRctCLSAGSimple(const key &, const ctkeyV &, const ctkey &, const key &, const key &, const multisig_kLRki *, key *, key *, unsigned int, hw::device &);
    bool verRctCLSAGSimple(const key &, const clsag &, const ctkeyV &, const key &);

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).
    void getKeyFromBlockchain(ctkey &a, size_t reference_index);
    std::tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin);

    rctSig genRctSimple(const key &message, const ctkeyV &inSk, const ctkeyV &inPk, const keyV &destinations, const std::vector<xmr_amount> &inamounts, const std::vector<xmr_amount> &outamounts, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, xmr_amount txnFee, unsigned int mixin, hw::device &hwdev);
    rctSig genRctSimple(const key &message, const ctkeyV &inSk, const keyV &destinations, const std::vector<xmr_amount> &inamounts, const std::vector<xmr_amount> &outamounts, xmr_amount txnFee, const ctkeyM &mixRing, const keyV &amount_keys, const std::vector<multisig_kLRki> *kLRki, multisig_out *msout, const std::vector<unsigned int> &index, ctkeyV &outSk, hw::device &hwdev);
    bool verRctSemanticsSimple(const rctSig &rv);
    bool verRctSemanticsSimple(const std::vector<const rctSig *> &rv);
    bool verRctNonSemanticsSimple(const rctSig &rv);

    xmr_amount decodeRctSimple(const rctSig &rv, const key &sk, unsigned int i, key &mask, hw::device &hwdev);
    xmr_amount decodeRctSimple(const rctSig &rv, const key &sk, unsigned int i, hw::device &hwdev);
    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev);
    bool signMultisig(rctSig &rv, const std::vector<unsigned int> &indices, const keyV &k, const multisig_out &msout, const key &secret_key);
} // namespace rct
#endif /* RCTSIGS_H */
