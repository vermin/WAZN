// Copyright (c) 2019-2021 WAZN Project
// Copyright (c) 2018-2020, The NERVA Project
// Copyright (c) 2014-2020, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "common/dns_config.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <functional>
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
    /**
   * @brief struct for loading a checkpoint from json
   */
    struct t_hashline
    {
        uint64_t height;  //!< the height of the checkpoint
        std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(height)
        KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
    };

    /**
   * @brief struct for loading many checkpoints from json
   */
    struct t_hash_json
    {
        std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
    };

    //---------------------------------------------------------------------------
    checkpoints::checkpoints()
    {
    }
    //---------------------------------------------------------------------------
    bool checkpoints::add_checkpoint(uint64_t height, const std::string &hash_str, const std::string &difficulty_str)
    {
        crypto::hash h = crypto::null_hash;
        bool r = epee::string_tools::hex_to_pod(hash_str, h);
        CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

        // return false if adding at a height we already have AND the hash is different
        if (m_points.count(height))
        {
            CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
        }
        m_points[height] = h;
        if (!difficulty_str.empty())
        {
            try
            {
                difficulty_type difficulty(difficulty_str);
                if (m_difficulty_points.count(height))
                {
                    CHECK_AND_ASSERT_MES(difficulty == m_difficulty_points[height], false, "Difficulty checkpoint at given height already exists, and difficulty for new checkpoint was different!");
                }
                m_difficulty_points[height] = difficulty;
            }
            catch (...)
            {
                LOG_ERROR("Failed to parse difficulty checkpoint: " << difficulty_str);
                return false;
            }
        }
        return true;
    }
    //---------------------------------------------------------------------------
    bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
    {
        return !m_points.empty() && (height <= (--m_points.end())->first);
    }
    //---------------------------------------------------------------------------
    bool checkpoints::check_block(uint64_t height, const crypto::hash &h, bool &is_a_checkpoint) const
    {
        auto it = m_points.find(height);
        is_a_checkpoint = it != m_points.end();
        if (!is_a_checkpoint)
            return true;

        if (it->second == h)
        {
            MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
            return true;
        }
        else
        {
            MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
            return false;
        }
    }
    //---------------------------------------------------------------------------
    bool checkpoints::check_block(uint64_t height, const crypto::hash &h) const
    {
        bool ignored;
        return check_block(height, h, ignored);
    }
    //---------------------------------------------------------------------------
    //FIXME: is this the desired behavior?
    bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
    {
        if (0 == block_height)
            return false;

        auto it = m_points.upper_bound(blockchain_height);
        // Is blockchain_height before the first checkpoint?
        if (it == m_points.begin())
            return true;

        --it;
        uint64_t checkpoint_height = it->first;
        return checkpoint_height < block_height;
    }
    //---------------------------------------------------------------------------
    uint64_t checkpoints::get_max_height() const
    {
        if (m_points.empty())
            return 0;
        return m_points.rbegin()->first;
    }
    //---------------------------------------------------------------------------
    const std::map<uint64_t, crypto::hash> &checkpoints::get_points() const
    {
        return m_points;
    }
    //---------------------------------------------------------------------------
    const std::map<uint64_t, difficulty_type> &checkpoints::get_difficulty_points() const
    {
        return m_difficulty_points;
    }

    bool checkpoints::check_for_conflicts(const checkpoints &other) const
    {
        for (auto &pt : other.get_points())
        {
            if (m_points.count(pt.first))
            {
                CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
            }
        }
        return true;
    }

    bool checkpoints::init_default_checkpoints(network_type nettype)
    {
        if (nettype == TESTNET)
        {
            return true;
        }
        if (nettype == STAGENET)
        {
            return true;
        }
        //ADD_CHECKPOINT(height, hash);
        //ADD_CHECKPOINT(1, "4636abd13b1b7b9258ff84bf1fde1a82e62c9e751daa94b3fcf7412e212a7198");
        //ADD_CHECKPOINT(2, "3e79b719c2b779f68cf2fcd2d787f875b719435f08540765c3484e66e3604b92");
        //ADD_CHECKPOINT(3, "0fe3a760d2ae216b25a0b4ebfe189e794d7e54cac208911b3965d6604a793149");
        //ADD_CHECKPOINT(10, "48e45cbb80fb02b38684bb7d7f809e4d09b7ab14d03f6f679c6814efc8ae5d09");
        //ADD_CHECKPOINT(100, "da432355d8619438dfe786a95c7b96a3bd03242d0126c49d04971f0c8d2758b2");
        //ADD_CHECKPOINT(250, "56e74ddf967bb37a1abd983f0a4c2ba03e8a91aeb34083d2d9ef25bf9d9eb9b7");
        //ADD_CHECKPOINT(1500, "aa2b0c3388e325dc5ab15fa8c841667d86f4e1d4c807b88cdae60b3d2bd4e4ea");
        //ADD_CHECKPOINT(10000, "2ace50209d7bd5428280c29384387703053de9618e5e2fb05401854b4a807758");
        //ADD_CHECKPOINT(48000, "4c176418847d1a2520e7076ed5e608f0094cb913931acd2e7f46487ce390a71d");
        //ADD_CHECKPOINT(65000, "0d59e7e528d056a3506c4b057106f5968f95565cc210e5bb15a19e8efe835025");
        //ADD_CHECKPOINT(80000, "6430683d9c963c2ddaf7ae741f0e833e33790be10e03e5b33e8dacb44925cc3e");
        //ADD_CHECKPOINT(100000, "83d0d466ab3c7d2edcaf93d821ae3dfffe599a17178fdff3d3d708e609406d61");
        //ADD_CHECKPOINT(120000, "b8b33042d451e55f640441cba9994f18bb4719242879fc6bef80ea497eefbb5b");
        //ADD_CHECKPOINT(140000, "9feed93420498408ab80546f700429d14c4fd39f7f72fa20b6bea8b76546ad39");
        //ADD_CHECKPOINT(150000, "f3a442e1f8bde3a774906f18ed94dee973ae0e9b32f7a2cb3bdf0797b6b7ed9e");
        return true;
    }

    bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
    {
        boost::system::error_code errcode;
        if (!(boost::filesystem::exists(json_hashfile_fullpath, errcode)))
        {
            LOG_PRINT_L1("Blockchain checkpoints file not found");
            return true;
        }

        LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

        uint64_t prev_max_height = get_max_height();
        LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
        t_hash_json hashes;
        if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
        {
            MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
            return false;
        }
        for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end();)
        {
            uint64_t height;
            height = it->height;
            if (height <= prev_max_height)
            {
                LOG_PRINT_L1("ignoring checkpoint height " << height);
            }
            else
            {
                std::string blockhash = it->hash;
                LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
                ADD_CHECKPOINT(height, blockhash);
            }
            ++it;
        }

        return true;
    }

    bool checkpoints::load_checkpoints_from_dns(network_type nettype)
    {
        std::vector<std::string> records;

        if (!tools::dns_utils::load_txt_records_from_dns(records, dns_config::get_config(nettype).CHECKPOINTS))
            return true; // why true ?

        for (const auto &record : records)
        {
            auto pos = record.find(":");
            if (pos != std::string::npos)
            {
                uint64_t height;
                crypto::hash hash;

                // parse the first part as uint64_t,
                // if this fails move on to the next record
                std::stringstream ss(record.substr(0, pos));
                if (!(ss >> height))
                {
                    continue;
                }

                // parse the second part as crypto::hash,
                // if this fails move on to the next record
                std::string hashStr = record.substr(pos + 1);
                if (!epee::string_tools::hex_to_pod(hashStr, hash))
                {
                    continue;
                }

                ADD_CHECKPOINT(height, hashStr);
            }
        }
        return true;
    }

    bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
    {
        bool result;

        result = load_checkpoints_from_json(json_hashfile_fullpath);
        if (dns)
        {
            result &= load_checkpoints_from_dns(nettype);
        }

        return result;
    }
} // namespace cryptonote
