"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../index");
const key_spec_1 = require("./key.spec");
async function testwithed25519() {
    const keyAgreementKey = await (0, key_spec_1.Ed25519Keypair)(key_spec_1.authenticationKey);
    console.log(keyAgreementKey);
    // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
    const hsCipher = new index_1.HypersignCipher({
        keyResolver: key_spec_1.hypersignDIDKeyResolverForEd25519KeyPair,
        keyAgreementKey
    });
    const messsage = { 'foo': 'bar12312' };
    const { jwe } = await hsCipher.encryptObject({ plainObject: messsage });
    console.log(jwe);
    const plainobject = await hsCipher.decryptObject({ jwe });
    console.log(plainobject);
}
async function testwithex25519() {
    const keyAgreementKey = await (0, key_spec_1.X25519KeyAgreementKeyPair)(key_spec_1.authenticationKey);
    // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
    const hsCipher = new index_1.HypersignCipher({
        keyResolver: key_spec_1.hypersignDIDKeyResolverForX25519KeyPair,
        keyAgreementKey
    });
    const messsage = { 'foo': 'bar12312' };
    const { jwe } = await hsCipher.encryptObject({ plainObject: messsage });
    console.log(jwe);
    const plainobject = await hsCipher.decryptObject({ jwe });
    console.log(plainobject);
}
testwithed25519();
testwithex25519();
