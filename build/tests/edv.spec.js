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
const x25519_key_agreement_key_2020_1 = require("@digitalbazaar/x25519-key-agreement-key-2020");
function createClient() {
    return __awaiter(this, void 0, void 0, function* () {
        const url = 'http://localhost:3001';
        const ed25519Keypair = yield (0, key_spec_1.Ed25519Keypair)(key_spec_1.authenticationKey);
        const x25519KeyPair = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020(ed25519Keypair);
        return (0, index_1.HypersignEdvClient)({ keyResolver: key_spec_1.hypersignDIDKeyResolverForEd25519KeyPair, url, invocationKeyPair: ed25519Keypair, keyagreementKeyPair: x25519KeyPair });
    });
}
function register() {
    return __awaiter(this, void 0, void 0, function* () {
        const hsEDVClient = yield createClient();
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
        const data = yield hsEDVClient.registerEdv(config);
        console.log(data);
        const edvId = data.id;
        console.log('New edvId is: ' + edvId);
        const m = { 'foo': 'bar' };
        // Inserting a doc in edv
        const res = yield hsEDVClient.insertDoc({
            document: m,
            edvId,
        });
        console.log(res);
        // updating a doc 1st time
        m.foo = 'bar2';
        const { id } = res.document;
        const res2 = yield hsEDVClient.updateDoc({ document: m, documentId: id, edvId });
        console.log(res2);
        //updating a doc 2nd time with same sequence (default will be 0)
        m.foo = 'bar3';
        const res3 = yield hsEDVClient.updateDoc({ document: m, documentId: id, edvId });
        console.log(res3);
        //updating a doc 3rd time with new sequence 
        m.foo = 'bar34';
        const res4 = yield hsEDVClient.updateDoc({ document: m, documentId: id, sequence: 1, edvId });
        console.log(res4);
        // Fetching a doc with doc id from edv:  it shoul return 2 docs
        const res5 = yield hsEDVClient.fetchDoc({ documentId: id, edvId });
        console.log(res5);
    });
}
register();
