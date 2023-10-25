import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';


export const authenticationKey = {
    '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
    id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
    controller: 'did:test:controller',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
    privateKeyMultibase: 'zrv2gheftP7VGPVoaJ7TbxGCN7pVXescn9FudB4xpF2HMWyjvzHuGVyPAb1NUeUGqqMxfHxgHiuLtR3pN5xyp8WLHR4'
}

export async function Ed25519Keypair(key = authenticationKey){
    const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519VerificationKey2020.generate({ ...key });
    return ed25519KeyPair;
}   

export  async function X25519KeyAgreementKeyPair(key = authenticationKey){
    // Now we can generate Ed25519VerificationKey2020 key pair
    const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519VerificationKey2020.generate({ ...key });
    // Finally we can convert into X25519KeyAgreementKey2020
    return X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair: ed25519KeyPair });
}

export const hypersignDIDKeyResolverForEd25519KeyPair = async ({id}) => {
  id
    // TODO: The id passed here is a verificationmethodId, we can query the DID document to fetch ed25519 authentication keys
    // Then convert ed25519 pair into X25519KeyAgreementKey2020 , so let's mock it. 
  
    // say we get this verificationMEthod after quering from our DID document
    // Example: const authnKey = didDoc.getVerificationMethod({proofPurpose: 'authentication'});
    const authenticationKey = {
      '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
      id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
      controller: 'did:test:controller',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
      privateKeyMultibase: ""
    }
  
    const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519Keypair(authenticationKey);
    return ed25519KeyPair;
}


// It takes verificaiton method as input and returns 
// This method will not have privat ekey.
export const hypersignDIDKeyResolverForX25519KeyPair = async ({id}) => {
  id
    // TODO: The id passed here is a verificationmethodId, we can query the DID document to fetch ed25519 authentication keys
    // Then convert ed25519 pair into X25519KeyAgreementKey2020 , so let's mock it. 
  
    // say we get this verificationMEthod after quering from our DID document
    // Example: const authnKey = didDoc.getVerificationMethod({proofPurpose: 'authentication'});
    const authenticationKey = {
      '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
      id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
      controller: 'did:test:controller',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
      privateKeyMultibase: ""
    }
  
  
    // const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519VerificationKey2020.generate({ ...authenticationKey });
    // return ed25519KeyPair;
    
    
    const keyAgreementKeyPair = await X25519KeyAgreementKeyPair(authenticationKey)
    return keyAgreementKeyPair
  
    // // Use veres driver to fetch the authn key directly
    // const keyPair = await Ed25519VerificationKey2020.from(await veresDriver.get({did: id}));
    // // Convert authn key to key agreement key
    // return X25519KeyPair.fromEd25519VerificationKey2020({keyPair});
  }
  
