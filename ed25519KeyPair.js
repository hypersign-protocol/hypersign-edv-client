import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

export async function getEd25519KeyPair(){
 const keyId = 'did:key:foo';
 const controller = 'did:test:controller';
 const _id = `${keyId}:12312312312`;
 return await Ed25519VerificationKey2020.generate({controller, id: _id});
}

