"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const HypersignEdvClientEd25519VerificationKey2020_1 = __importDefault(require("./HypersignEdvClientEd25519VerificationKey2020"));
const HypersignEdvClientEcdsaSecp256k1_1 = __importDefault(require("./HypersignEdvClientEcdsaSecp256k1"));
var invocationType;
(function (invocationType) {
    invocationType["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020";
    invocationType["HypersignEdvClientEcdsaSecp256k1"] = "HypersignEdvClientEcdsaSecp256k1";
})(invocationType || (invocationType = {}));
var keyagreementType;
(function (keyagreementType) {
    keyagreementType["X25519KeyAgreementKey2020"] = "X25519KeyAgreementKey2020";
    keyagreementType["X25519KeyAgreementKeyEIP5630"] = "X25519KeyAgreementKeyEIP5630";
})(keyagreementType || (keyagreementType = {}));
function HypersignEdvClient(params) {
    // : HypersignEdvClientEcdsaSecp256k1 | HypersignEdvClientEd25519VerificationKey2020
    if (!params.url)
        throw new Error('edvsUrl is required');
    if (!params.invocationKeyPair)
        throw new Error('InvocationKeyPair is required');
    if (!params.keyagreementKeyPair)
        throw new Error('KeyAgreementKeyPair is required');
    if (!params.invocationKeyPair.id)
        throw new Error('InvocationKeyPair.id is required');
    if (!params.invocationKeyPair.type)
        throw new Error('InvocationKeyPair.type is required');
    if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 && !params.invocationKeyPair.publicKeyMultibase)
        throw new Error('InvocationKeyPair.publicKeyMultibase is required');
    if (params.invocationKeyPair.type === invocationType.HypersignEdvClientEcdsaSecp256k1 &&
        !params.invocationKeyPair.blockchainAccountId)
        throw new Error('InvocationKeyPair.blockchainAccountId is required');
    if (!params.keyagreementKeyPair.id)
        throw new Error('KeyAgreementKeyPair.id is required');
    if (!params.keyagreementKeyPair.type)
        throw new Error('KeyAgreementKeyPair.type is required');
    if (params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020 &&
        !params.keyagreementKeyPair.publicKeyMultibase)
        throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
    if (params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKeyEIP5630 &&
        !params.keyagreementKeyPair.publicKeyMultibase)
        throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
    if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 &&
        params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020) {
        if (!params.keyResolver)
            throw new Error('keyResolver is required');
        return new HypersignEdvClientEd25519VerificationKey2020_1.default({
            url: params.url,
            ed25519VerificationKey2020: params.invocationKeyPair,
            x25519KeyAgreementKey2020: params.keyagreementKeyPair,
            keyResolver: params.keyResolver,
            shaHmacKey2020: params.shaHmacKey2020,
        });
    }
    else {
        return new HypersignEdvClientEcdsaSecp256k1_1.default({
            url: params.url,
            verificationMethod: params.invocationKeyPair,
            // Type Definition Inline
            keyAgreement: {
                id: params.keyagreementKeyPair.id,
                type: 'X25519KeyAgreementKeyEIP5630',
                publicKeyMultibase: params.keyagreementKeyPair.publicKeyMultibase,
                controller: params.keyagreementKeyPair.controller,
            },
        });
    }
}
exports.default = HypersignEdvClient;
