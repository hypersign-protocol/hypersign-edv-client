"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
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
const minimal_cipher_1 = require("@digitalbazaar/minimal-cipher");
const x25519_key_agreement_key_2020_1 = require("@digitalbazaar/x25519-key-agreement-key-2020");
const hsEdvDataModels_1 = require("./hsEdvDataModels");
const ed25519_verification_key_2020_1 = require("@digitalbazaar/ed25519-verification-key-2020");
class HypersignCipher {
    constructor({ keyResolver, keyAgreementKey }) {
        this.keyResolver = keyResolver;
        this.cipher = new minimal_cipher_1.Cipher();
        this.keyAgreementKey = keyAgreementKey;
    }
    _getX25519KeyAgreementKey(keyAgreementKey = this.keyAgreementKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (keyAgreementKey.type === hsEdvDataModels_1.VerificationKeyTypes.Ed25519VerificationKey2020) {
                const ed25519KeyPair = yield ed25519_verification_key_2020_1.Ed25519VerificationKey2020.generate(Object.assign({}, keyAgreementKey));
                const keyAgreementKeyPair = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
                    keyPair: ed25519KeyPair,
                });
                return keyAgreementKeyPair;
            }
            else if (keyAgreementKey.type === hsEdvDataModels_1.KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
                return keyAgreementKey;
            }
            else {
                throw new Error('Unsupported type  ' + keyAgreementKey.type);
            }
        });
    }
    // TODO: bas way of doing it
    _getX25519KeyAgreementResolver(keyResolver = this.keyResolver, id) {
        return __awaiter(this, void 0, void 0, function* () {
            const keypairObj = yield keyResolver({ id });
            if (keypairObj.type === hsEdvDataModels_1.VerificationKeyTypes.Ed25519VerificationKey2020) {
                const keyAgreementKeyPair = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
                    keyPair: keypairObj,
                });
                return () => __awaiter(this, void 0, void 0, function* () {
                    return keyAgreementKeyPair;
                });
            }
            else if (keypairObj.type === hsEdvDataModels_1.KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
                return keyResolver;
            }
            else {
                throw new Error('Unsupported type  ' + keypairObj.type);
            }
        });
    }
    resolver({ id }) {
        return __awaiter(this, void 0, void 0, function* () {
            const pubkey = id.split('#')[1];
            let keyPair = {
                publicKeyMultibase: '',
            };
            keyPair.publicKeyMultibase = pubkey;
            const keyAgreementKeyPair = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.from({
                publicKeyMultibase: keyPair.publicKeyMultibase,
                id,
            });
            return keyAgreementKeyPair;
        });
    }
    // helper to create default recipients
    _createDefaultRecipients(keyAgreementKey) {
        return keyAgreementKey
            ? [
                {
                    header: {
                        kid: keyAgreementKey.id,
                        // only supported algorithm
                        alg: 'ECDH-ES+A256KW',
                    },
                },
            ]
            : [];
    }
    _createParticipants(recipients) {
        return recipients.map((recipient) => {
            if (recipient.type === 'X25519KeyAgreementKey2020') {
                const pubkey = recipient.id.split('#')[1];
                const id = recipient.id.split('#')[0];
                let keyPair = {
                    publicKeyMultibase: '',
                };
                keyPair.publicKeyMultibase = pubkey;
                const x25519keyAgreementKeyPub = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair });
                return {
                    header: {
                        kid: id + '#' + x25519keyAgreementKeyPub.publicKeyMultibase,
                        // only supported algorithm
                        alg: 'ECDH-ES+A256KW',
                    },
                };
            }
            else {
                // comming soon
            }
        });
    }
    encryptObject({ plainObject, recipients = [], keyResolver = this.keyResolver, keyAgreementKey = this.keyAgreementKey, }) {
        return __awaiter(this, void 0, void 0, function* () {
            // worng way of doing it
            const x25519keyAgreementKey = yield this._getX25519KeyAgreementKey(keyAgreementKey);
            if (recipients.length === 0 && x25519keyAgreementKey) {
                recipients = this._createDefaultRecipients(x25519keyAgreementKey);
            }
            else {
                recipients = this._createParticipants(recipients);
            }
            // keyResolver is required because Notice that recipients lists only key IDs, not the keys themselves.
            // A keyResolver is a function that accepts a key ID and resolves to the public key corresponding to it.
            const kr = yield this.resolver;
            const jwe = yield this.cipher.encryptObject({ obj: plainObject, recipients, keyResolver: kr });
            return jwe;
        });
    }
    decryptObject({ jwe, keyAgreementKey = this.keyAgreementKey }) {
        return __awaiter(this, void 0, void 0, function* () {
            const x25519keyAgreementKey = yield this._getX25519KeyAgreementKey(keyAgreementKey);
            const object = yield this.cipher.decryptObject({ jwe, keyAgreementKey: x25519keyAgreementKey });
            return object;
        });
    }
}
exports.default = HypersignCipher;
