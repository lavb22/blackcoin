// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"
#include "script.h"

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)){

    	LOCK(cs_KeyStore);
    	        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    	        if (it != mapWatchKeys.end()) {
    	            vchPubKeyOut = it->second;
    	            return true;
    	        }
        return false;}
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript() : redeemScripts > %i bytes are invalid", MAX_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[redeemScript.GetID()] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}


//Agregado para importaddress

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
	std::vector<valtype> vSolutions;
	    txnouttype whichType;
	    if (!Solver(dest, whichType, vSolutions))
	        return false;

	    switch (whichType)
	    {
	    case TX_NONSTANDARD:
	    	return false;
	    case TX_NULL_DATA:
	        return false;
	    case TX_PUBKEY:
	        pubKeyOut = CPubKey(vSolutions[0]);
	        return true;
	    case TX_PUBKEYHASH:
	    	return false;
	    case TX_SCRIPTHASH:
	        return false;
	    case TX_MULTISIG:
	    	return false;
	    }
	    return false;
    //TODO: Use Solver to extract this?
  /*  CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;*/
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest, const CKeyID &keyAdd)
{
    LOCK(cs_KeyStore);
    CPubKey pubKey;
    setWatchOnly.insert(keyAdd);
    setScriptWatchOnly.insert(dest.GetID());
    if (ExtractPubKey(dest, pubKey))
    	mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setScriptWatchOnly.erase(dest.GetID());
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setScriptWatchOnly.count(dest.GetID()) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}



