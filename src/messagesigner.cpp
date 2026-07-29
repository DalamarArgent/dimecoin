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

namespace {
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

    // Compatibility fallback for mixed networks that still sign with older magic.
    const std::string kAltMagic1 = "DarkCoin Signed Message:\n";
    const std::string kAltMagic2 = "Dimecoin Signed Message:\n";

    const std::string primaryError = strErrorRet;
    std::string altError;

    if (strMessageMagic != kAltMagic1 && VerifyMessageWithMagic(pubkey, vchSig, strMessage, kAltMagic1, altError)) {
        return true;
    }
    if (strMessageMagic != kAltMagic2 && VerifyMessageWithMagic(pubkey, vchSig, strMessage, kAltMagic2, altError)) {
        return true;
    }

    strErrorRet = primaryError;
    return false;
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
