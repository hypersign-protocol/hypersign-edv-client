import { HypersignCipher } from '../index';
import { X25519KeyAgreementKeyPair, Ed25519Keypair, authenticationKey, hypersignDIDKeyResolverForEd25519KeyPair, hypersignDIDKeyResolverForX25519KeyPair } from './key.spec'


async function testwithed25519(){
    const keyAgreementKey = await Ed25519Keypair(authenticationKey)
    console.log(keyAgreementKey)
    // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
    const hsCipher = new HypersignCipher({
      keyResolver: hypersignDIDKeyResolverForEd25519KeyPair, 
      keyAgreementKey
    })
    const messsage = { 'foo': 'bar12312' }
    const jwe  = await hsCipher.encryptObject({ plainObject: messsage});
    console.log(jwe)

    const plainobject  = await hsCipher.decryptObject({jwe});
    console.log(plainobject)
}

async function testwithex25519(){
  const keyAgreementKey = await X25519KeyAgreementKeyPair(authenticationKey)
  // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
  const hsCipher = new HypersignCipher({
    keyResolver: hypersignDIDKeyResolverForX25519KeyPair, 
    keyAgreementKey
  })
  const messsage = { 'foo': 'bar12312' }
  const jwe  = await hsCipher.encryptObject({ plainObject: messsage});
  console.log(jwe)

  const plainobject  = await hsCipher.decryptObject({jwe});
  console.log(plainobject)
}

testwithed25519()

testwithex25519();







