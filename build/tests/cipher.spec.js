"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../index");
const key_spec_1 = require("./key.spec");
function testwithed25519() {
    return __awaiter(this, void 0, void 0, function* () {
        const keyAgreementKey = yield (0, key_spec_1.Ed25519Keypair)(key_spec_1.authenticationKey);
        console.log(keyAgreementKey);
        // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
        const hsCipher = new index_1.HypersignCipher({
            keyResolver: key_spec_1.hypersignDIDKeyResolverForEd25519KeyPair,
            keyAgreementKey
        });
        const messsage = { 'foo': 'bar12312' };
        const { jwe } = yield hsCipher.encryptObject({ plainObject: messsage });
        console.log(jwe);
        const plainobject = yield hsCipher.decryptObject({ jwe });
        console.log(plainobject);
    });
}
function testwithex25519() {
    return __awaiter(this, void 0, void 0, function* () {
        const keyAgreementKey = yield (0, key_spec_1.X25519KeyAgreementKeyPair)(key_spec_1.authenticationKey);
        // This should work with both resolver hypersignDIDKeyResolverForEd25519KeyPair and hypersignDIDKeyResolverForX25519KeyPair
        const hsCipher = new index_1.HypersignCipher({
            keyResolver: key_spec_1.hypersignDIDKeyResolverForX25519KeyPair,
            keyAgreementKey
        });
        const messsage = { 'foo': 'bar12312' };
        const { jwe } = yield hsCipher.encryptObject({ plainObject: messsage });
        console.log(jwe);
        const plainobject = yield hsCipher.decryptObject({ jwe });
        console.log(plainobject);
    });
}
testwithed25519();
testwithex25519();
