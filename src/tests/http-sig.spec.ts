import HypersignZCapHttpSigner from '../hsZCapHttpSig';
import {  Ed25519Keypair } from './key.spec'
const keyResolverEd25519 = async () => {
    return {
        id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
        controller: 'did:test:controller',
        type: 'Ed25519VerificationKey2020',
        publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
        privateKeyMultibase: 'zrv2gheftP7VGPVoaJ7TbxGCN7pVXescn9FudB4xpF2HMWyjvzHuGVyPAb1NUeUGqqMxfHxgHiuLtR3pN5xyp8WLHR4',
    }
}

async function test(){
    const keypair = await Ed25519Keypair();
    const hsCipher = new HypersignZCapHttpSigner({ keyAgreementKey: keypair })
    
    const BASE_URL = 'http://localhost:3001';

    const edvId = '62473c97-283c-4369-832e-587778255611';
    const url = `${BASE_URL}/api/v1/edvs/${edvId}/docs`;

    const signedHeader = await hsCipher.signHTTP({
        url, 
        method: 'POST',
        headers: {
            controller: keypair.controller,
            vermethodid: keypair.id,
            date: new Date().toUTCString()
        }, 
        encryptedObject: {'foo': 'bar'}, 
        capabilityAction: 'write'
    });
      
    console.log(signedHeader)
}


test();
