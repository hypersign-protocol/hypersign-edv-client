import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { signCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-invoke';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { verifyCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-verify'
import { CryptoLD } from 'crypto-ld';
import { constants as securityContextConstants } from 'security-context';
import { getEd25519KeyPair } from './ed25519KeyPair.js';

const { SECURITY_CONTEXT_V2_URL } = securityContextConstants;
import {
  createRootCapability,
  documentLoader as zcapDocLoader
} from '@digitalbazaar/zcap';


// We can support more keys like RSA here
const keyPairs = [{
  name: 'Ed25519VerificationKey2020',
  KeyPair: Ed25519VerificationKey2020,
  Suite: Ed25519Signature2020
}];

const { KeyPair, Suite } = keyPairs[0];
// const keyId = 'did:key:foo';
// const controller = 'did:test:controller';
// const _id = `${keyId}:12312312312`;
const keyPair123 = await getEd25519KeyPair() //KeyPair.generate({ controller, id: _id });
const controller = keyPair123.controller
console.log('Generating Ed25519VerificationKey2020 keypair...........')
console.log({ keyPair123: keyPair123.export({ publicKey: true, includeContext: true }) })

const TEST_URL = 'https://www.test.org/read/foo';
const method = 'GET';

async function signHTTPRequest() {
  console.log('Singning http request using Ed25519VerificationKey2020 privatekey/signer...........')
  const signed = await signCapabilityInvocation({
    url: TEST_URL,
    method,
    headers: {
      date: new Date().toUTCString()
    },
    json: { foo: true },
    invocationSigner: keyPair123.signer(),
    capabilityAction: 'read'
  });

  console.log(signed)
  await verifyHTTPRequest({ signed, Suite, keyPair: keyPair123 })
}

async function verifyHTTPRequest({ signed, Suite, keyPair }) {
  console.log('Verifiying http request using Ed25519VerificationKey2020 ...........')

  const { host } = new URL(TEST_URL);
  signed.host = signed.host || host;

  const keyId = keyPair.id;

  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });
  const documentLoader = async uri => {
    if (uri === controller) {
      const doc = {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: controller,
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
  
  const rootCapability = createRootCapability({ controller, invocationTarget: TEST_URL });

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