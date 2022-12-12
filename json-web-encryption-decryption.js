import { Cipher } from '@digitalbazaar/minimal-cipher';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { getEd25519KeyPair } from './ed25519KeyPair.js';

async function start(){
  console.log('Preparing X25519KeyAgreementKey2020 from Ed25519VerificationKey2020 ...................');
  // Get Ed25519VerificationKey2020 
  const keyPair1 = await getEd25519KeyPair();
  // Convert to X25519KeyAgreementKey2020 key
  // X25519 is an elliptic curve Diffie-Hellman key exchange using Curve25519. 
  // It allows two parties to jointly agree on a shared secret using an insecure channel.
  const keyAgreementKey = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair: keyPair1 });
  // Add controllers and give it an Id if it is not given in Ed25519VerificationKey2020
  // keyAgreementKey.controller = !keyAgreementKey.controller ? "some-random-controller" : keyAgreementKey.controller;
  // keyAgreementKey.id = !keyAgreementKey.id ? `${keyAgreementKey.controller}#${keyAgreementKey.fingerprint()}`: keyAgreementKey.id;

  console.log({
    keyPair1,
    keyAgreementKey
  })

  
  console.log('Ready for encryption and decryption using X25519KeyAgreementKey2020 ...................');

  

  console.log('Plaing text ......')
  // Plain text object to sign
  const obj = { key: 'value' };
  console.log(obj)
  const cipher = new Cipher();


  // A list of recipients must be given in the `recipients` array, identified by key agreement keys.
  // An ephemeral ECDH key will be generated and used to derive shared KEKs that will wrap a randomly generated CEK.
  const recipient = {
    header: {
      kid: keyAgreementKey.id,
      alg: 'ECDH-ES+A256KW' // TODO: Need to find reference 
    }
  }
  const recipients = [recipient];
 

  // A function that returns a Promise that resolves a key ID to a DH public key.
  const keyResolver = async () => {
    return {
      '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
      id: keyAgreementKey.id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: keyAgreementKey.publicKeyMultibase
    }
  }
  
  // Encrypts some data for one or more recipients and outputs a JWE
  // To encrypt Uint8Array or a string;  use cipher.encrypt() The data to encrypt can be given as a Uint8Array or a string.
  // cipher.encryptObject Encrypts an object. The object will be serialized to JSON and passed
  // Doc: https://github.com/digitalbazaar/minimal-cipher/blob/main/lib/Cipher.js#L98
  // options.keyResolver - A function that returns a Promise that resolves a key ID to a DH public key.
  const jweDoc = await cipher.encryptObject({ obj, recipients, keyResolver });
  console.log('Encrypted text (JWE)......')
  console.log(jweDoc)

  const object = await cipher.decryptObject({ jwe: jweDoc, keyAgreementKey });
  console.log('Decrypted text ......')
  console.log(object)
}

start()