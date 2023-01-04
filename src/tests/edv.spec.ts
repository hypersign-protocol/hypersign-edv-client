import { HypersignEdvClient } from '../index';
import { Ed25519Keypair, authenticationKey, hypersignDIDKeyResolverForEd25519KeyPair } from './key.spec'

async function createClient() {
  const url = 'http://localhost:3001';
  const keyAgreementKey = await Ed25519Keypair(authenticationKey) 
  return new HypersignEdvClient({keyResolver: hypersignDIDKeyResolverForEd25519KeyPair, url, keyAgreementKey: keyAgreementKey});
}

async function register(){
  const hsEDVClient = await createClient();

  const config = {
    controller: 'did:example:123456789',
    keyAgreementKey: {
      id: 'https://example.com/kms/12345',
      type: 'X25519KeyAgreementKey2020',
    },
    hmac: {
      id: 'https://example.com/kms/67891',
      type: 'Sha256HmacKey2020',
    },
    edvId: "my-edv-1" // Optional 
  };
  
  const data  = await hsEDVClient.registerEdv(config);
  console.log(data);

  const edvId: string = data.id;
  console.log('New edvId is: ' + edvId);
  const m = { 'foo': 'bar' };

  const res = await hsEDVClient.insertDoc({document: m, documentId: 'my-doc-1' ,edvId});
  console.log(res)
}


register()





