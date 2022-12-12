import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { signCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-invoke';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { verifyCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-verify'
import { CryptoLD } from 'crypto-ld';
import { constants as securityContextConstants } from 'security-context';
import { getEd25519KeyPair } from './ed25519KeyPair.js';
import message from './message.js';
import {
  createRootCapability,
  documentLoader as zcapDocLoader
} from '@digitalbazaar/zcap';

// Preparing some gbl variables
const { SECURITY_CONTEXT_V2_URL } = securityContextConstants;
const TEST_URL = 'https://www.test.org/read/foo';
const method = 'GET';

// Get the key pair
const keyPair123 = await getEd25519KeyPair();
console.log('Generating Ed25519VerificationKey2020 keypair...........')
console.log({ keyPair123: keyPair123.export({ publicKey: true, privateKey:true, includeContext: true }) })

// Sign HTTP request
async function signHTTPRequest() {
  console.log('Singning http request using Ed25519VerificationKey2020 privatekey/signer...........')
  const signed = await signCapabilityInvocation({
    url: TEST_URL,
    method,
    headers: {
      // digest signature
      // authorization header
      date: new Date().toUTCString()
    },
    json: message, // should be encrypted message 
    invocationSigner: keyPair123.signer(),
    capabilityAction: 'read' // ''write|read''
  });

  console.log(signed)
  // Deleting the private key just to make we are accendentially not passing it to verify function
  delete keyPair123.privateKeyMultibase
  console.log(keyPair123)
  await verifyHTTPRequest({ signed, keyPair: keyPair123 })
}

// Verify HTTP request
async function verifyHTTPRequest({ signed, keyPair }) {
  console.log('Verifiying http request using Ed25519VerificationKey2020 ...........')

  const { host } = new URL(TEST_URL);
  signed.host = signed.host || host;

  const keyId = keyPair.id;

  // Using Ed25519Signature2020 suite
  const suite = new Ed25519Signature2020({
    verificationMethod: keyId,
    key: keyPair
  });
  const documentLoader = async uri => {
    if (uri === keyPair.controller) {
      const doc = {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: keyPair.controller,
        capabilityInvocation: [keyId]
      };
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    // when we dereference the keyId for verification
    // all we need is the publicNode
    if (uri === keyId) {
      const doc = keyPair.export({ publicKey: true, includeContext: true });
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    if (uri === rootCapability.id) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    return zcapDocLoader(uri);
  };

  const getVerifier = async  ({ keyId, documentLoader }) => {
    const cryptoLd = new CryptoLD();
    cryptoLd.use(Ed25519VerificationKey2020);
    const key = await cryptoLd.fromKeyId({ id: keyId, documentLoader });
    const verificationMethod = await key.export(
      { publicKey: true, includeContext: true });
    const verifier = key.verifier();
    return { verifier, verificationMethod };
  }
  
  const rootCapability = createRootCapability({ controller: keyPair123.controller, invocationTarget: TEST_URL });

  const { verified, error } = await verifyCapabilityInvocation({
    url: TEST_URL,
    method,
    suite,
    headers: signed,
    expectedAction: 'read',
    expectedHost: host,
    expectedRootCapability: rootCapability.id,
    expectedTarget: TEST_URL,
    keyId,
    documentLoader,
    getVerifier
  });
  console.log({
    verified, error: JSON.stringify(error)
  })
};

signHTTPRequest();

// TODO: Need to try sending the signed encrypted message. check the transmute edv client repo for reference
// await httpClient.post(url, {agent, json: encrypted, headers});


