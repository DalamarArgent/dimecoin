// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2013-2022 The Dimecoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <messagesigner.h>
#include <key_io.h>
#include <hash.h>
#include <validation.h> // For strMessageMagic
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <atomic>

namespace {
std::atomic<int64_t> g_legacy_magic_accepts{0};

bool VerifyMessageWithMagic(const CPubKey pubkey,
                            const std::vector<unsigned char>& vchSig,
                            const std::string& strMessage,
                            const std::string& strMagic,
                            std::string& strErrorRet)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMagic;
    ss << strMessage;

    return CHashSigner::VerifyHash(ss.GetHash(), pubkey, vchSig, strErrorRet);
}

bool LegacyMagicEnabled()
{
    // Read once: gArgs is fully populated before any net/masternode thread starts, and this sits
    // on a hot verification path (masternodeman.cpp walks every masternode calling VerifyMessage).
    static const bool fEnabled = gArgs.GetBoolArg("-legacysigmagic", DEFAULT_LEGACY_SIG_MAGIC);
    return fEnabled;
}

/** Record a signature that only verified under a legacy magic, and surface it to the operator.
 *  This is the removal trigger for the fallback: when a release cycle passes with no such log
 *  line, the network has migrated and the fallback (plus -legacysigmagic) can be deleted. */
void NoteLegacyMagicAccept()
{
    const int64_t nCount = ++g_legacy_magic_accepts;
    if (nCount == 1 || nCount % 1000 == 0) {
        LogPrintf("CMessageSigner -- WARNING: accepted %d signature(s) using a legacy message magic. "
                  "The -legacysigmagic fallback is still required by this network; it cannot be removed yet.\n", nCount);
    }
}
} // namespace

bool CMessageSigner::GetKeysFromSecret(const std::string strSecret, CKey& keyRet, CPubKey& pubkeyRet)
{
    keyRet = DecodeSecret(strSecret);
    if (!keyRet.IsValid()) return false;

    pubkeyRet = keyRet.GetPubKey();

    return true;
}

bool CMessageSigner::SignMessage(const std::string strMessage, std::vector<unsigned char>& vchSigRet, const CKey key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    return CHashSigner::SignHash(ss.GetHash(), key, vchSigRet);
}

bool CMessageSigner::VerifyMessage(const CPubKey pubkey, const std::vector<unsigned char>& vchSig, const std::string strMessage, std::string& strErrorRet)
{
    if (VerifyMessageWithMagic(pubkey, vchSig, strMessage, strMessageMagic, strErrorRet)) {
        return true;
    }

    if (!LegacyMagicEnabled()) {
        return false;
    }

    // Temporary compatibility fallback for mixed networks that still sign with the older magic.
    // Each attempt costs a full ECDSA pubkey recovery, so this only runs after the primary magic
    // has already failed, and only for magics that differ from the configured one.
    const std::string kAltMagic1 = "DarkCoin Signed Message:\n";
    const std::string kAltMagic2 = "Dimecoin Signed Message:\n";

    const std::string primaryError = strErrorRet;
    std::string altError;

    if (strMessageMagic != kAltMagic1 && VerifyMessageWithMagic(pubkey, vchSig, strMessage, kAltMagic1, altError)) {
        NoteLegacyMagicAccept();
        return true;
    }
    if (strMessageMagic != kAltMagic2 && VerifyMessageWithMagic(pubkey, vchSig, strMessage, kAltMagic2, altError)) {
        NoteLegacyMagicAccept();
        return true;
    }

    strErrorRet = primaryError;
    return false;
}

int64_t CMessageSigner::GetLegacyMagicAcceptCount()
{
    return g_legacy_magic_accepts.load();
}

bool CHashSigner::SignHash(const uint256& hash, const CKey key, std::vector<unsigned char>& vchSigRet)
{
    return key.SignCompact(hash, vchSigRet);
}

bool CHashSigner::VerifyHash(const uint256& hash, const CPubKey pubkey, const std::vector<unsigned char>& vchSig, std::string& strErrorRet)
{
    CPubKey pubkeyFromSig;
    if(!pubkeyFromSig.RecoverCompact(hash, vchSig)) {
        strErrorRet = "Error recovering public key.";
        return false;
    }

    if(pubkeyFromSig.GetID() != pubkey.GetID()) {
        strErrorRet = strprintf("Keys don't match: pubkey=%s, pubkeyFromSig=%s, hash=%s, vchSig=%s",
                    pubkey.GetID().ToString(), pubkeyFromSig.GetID().ToString(), hash.ToString(),
                    EncodeBase64(&vchSig[0], vchSig.size()));
        return false;
    }

    return true;
}
