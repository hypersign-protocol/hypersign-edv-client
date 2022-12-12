import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import pkg from '@cosmjs/crypto';

const {  Slip10RawIndex, Bip39, EnglishMnemonic } = pkg;
import HypersignSsiSDK from 'hs-ssi-sdk';
function makeCosmoshubPath(a) {
    return [
        Slip10RawIndex.hardened(44),
        Slip10RawIndex.hardened(118),
        Slip10RawIndex.hardened(0),
        Slip10RawIndex.normal(0),
        Slip10RawIndex.normal(a),

    ];
}
const createWallet = async (mnemonic) => {
    if (!mnemonic) {
        return await DirectSecp256k1HdWallet.generate(24, {
            prefix: "hid",
            hdPaths: [makeCosmoshubPath(0)],
        });
    } else {
        return await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
            prefix: "hid",
            hdPaths: [makeCosmoshubPath(0)],
        });
    }
}
const hidNodeEp = {
    rpc: "https://jagrat.hypersign.id/rpc",
    rest: "https://jagrat.hypersign.id/rest",
    namespace: 'testnet'
}

export async function getEd25519KeyPair() {
    const mnemonic = new EnglishMnemonic("napkin delay purchase easily camp mimic share wait stereo reflect allow soccer believe exhibit laptop upset tired talent transfer talk surface solution omit crack")
    const wallet = await createWallet() /// offline Signer
    const hsSdk = new HypersignSsiSDK(wallet, hidNodeEp.rpc, hidNodeEp.rest, hidNodeEp.namespace);
    await hsSdk.init()
    const seed = Bip39.decode(mnemonic) // seed for keys 



    const didKeys = await hsSdk.did.generateKeys({ seed }) // generate keys from seed
    
    
    
    // const did = await hsSdk.did.generate({    // generate did from keys
    //     publicKeyMultibase: didKeys.publicKeyMultibase,
    // })    

    
    const {didDocument}=await hsSdk.did.resolve({
        did:'did:hid:testnet:zBsgb2aLJfMZArfXwjejSX8gMVz1k5zhf5bEn3WACz2wG',
        ed25519verificationkey2020:true
    })
    
    const kp = await Ed25519VerificationKey2020.from({    // generate Ed25519VerificationKey2020 Object from keys
         // Key ID
        controller: didDocument.id, // Key Controller 
        type:Ed25519VerificationKey2020.SUITE_ID,
        publicKeyMultibase: didDocument.verificationMethod[0].publicKeyMultibase,
        privateKeyMultibase: didKeys.privateKeyMultibase,
    })
    return kp;
}




getEd25519KeyPair()

