import { HypersignEdvClient } from '../index';
import { Ed25519Keypair, X25519KeyAgreementKeyPair, authenticationKey, hypersignDIDKeyResolverForEd25519KeyPair } from './key.spec'
import {X25519KeyAgreementKey2020} from '@digitalbazaar/x25519-key-agreement-key-2020'
async function createClient() {
  const url = 'http://localhost:3001';
  const ed25519Keypair = await Ed25519Keypair(authenticationKey) 
  const x25519KeyPair=X25519KeyAgreementKey2020.fromEd25519VerificationKey2020(ed25519Keypair)
  return  HypersignEdvClient({keyResolver: hypersignDIDKeyResolverForEd25519KeyPair, url, invocationKeyPair:  ed25519Keypair,keyagreementKeyPair:x25519KeyPair});
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
  // Registering the edv
  const data  = await hsEDVClient.registerEdv(config);
  console.log(data);

  const edvId: string = data.id;
  console.log('New edvId is: ' + edvId)
  const m = { 'foo': 'bar' };

  // Inserting a doc in edv
  const res = await hsEDVClient.insertDoc({document: m, edvId});
  console.log(res)

  // updating a doc 1st time
  m.foo = 'bar2'; 
  const { id } = res; 
  const res2 = await hsEDVClient.updateDoc({document: m, documentId: id, edvId});
  console.log(res2)

  //updating a doc 2nd time with same sequence (default will be 0)
  m.foo = 'bar3'; 
  const res3 = await hsEDVClient.updateDoc({document: m, documentId: id, edvId});
  console.log(res3)

  //updating a doc 3rd time with new sequence 
  m.foo = 'bar34'; 
  const res4 = await hsEDVClient.updateDoc({document: m, documentId: id, sequence: 1 , edvId});
  console.log(res4)

  // Fetching a doc with doc id from edv:  it shoul return 2 docs
  const res5 = await hsEDVClient.fetchDoc({ documentId: id, edvId });
  console.log(res5)


}


register()





