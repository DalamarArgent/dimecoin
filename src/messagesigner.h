// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2013-2022 The Dimecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MESSAGESIGNER_H
#define MESSAGESIGNER_H

#include <key.h>
#include <script/standard.h>

/** Accept masternode-layer signatures made under the legacy "DarkCoin"/"Dimecoin" message magic
 *  in addition to the currently configured strMessageMagic.
 *
 *  This is migration scaffolding, not a permanent feature. Removal criteria: once a full release
 *  cycle passes with no "accepted N signature(s) using a legacy message magic" warning in
 *  debug.log, drop the fallback, this option, and CMessageSigner::GetLegacyMagicAcceptCount(). */
static const bool DEFAULT_LEGACY_SIG_MAGIC = true;

/** Helper class for signing messages and checking their signatures
 */
class CMessageSigner
{
public:
    /// Set the private/public key values, returns true if successful
    static bool GetKeysFromSecret(const std::string strSecret, CKey& keyRet, CPubKey& pubkeyRet);
    /// Sign the message, returns true if successful
    static bool SignMessage(const std::string strMessage, std::vector<unsigned char>& vchSigRet, const CKey key);
    /// Verify the message signature, returns true if succcessful
    static bool VerifyMessage(const CPubKey pubkey, const std::vector<unsigned char>& vchSig, const std::string strMessage, std::string& strErrorRet);
    /// How many signatures have only verified under a legacy magic string. Zero over a full
    /// release cycle is the signal that the fallback above can be removed.
    static int64_t GetLegacyMagicAcceptCount();
};

/** Helper class for signing hashes and checking their signatures
 */
class CHashSigner
{
public:
    /// Sign the hash, returns true if successful
    static bool SignHash(const uint256& hash, const CKey key, std::vector<unsigned char>& vchSigRet);
    /// Verify the hash signature, returns true if succcessful
    static bool VerifyHash(const uint256& hash, const CPubKey pubkey, const std::vector<unsigned char>& vchSig, std::string& strErrorRet);
};

#endif
