/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import HypersignEdvClientEd25519VerificationKey2020 from './HypersignEdvClientEd25519VerificationKey2020';
import { KeyResolver } from './Types';
import HypersignEdvClientEcdsaSecp256k1 from './HypersignEdvClientEcdsaSecp256k1';
declare enum invocationType {
    Ed25519VerificationKey2020 = "Ed25519VerificationKey2020",
    HypersignEdvClientEcdsaSecp256k1 = "HypersignEdvClientEcdsaSecp256k1"
}
declare enum keyagreementType {
    X25519KeyAgreementKey2020 = "X25519KeyAgreementKey2020",
    X25519KeyAgreementKeyEIP5630 = "X25519KeyAgreementKeyEIP5630"
}
interface InvocationKeyPair {
    id: string;
    type: invocationType;
    controller: string;
    publicKeyMultibase: string;
    blockchainAccountId: string;
    privateKeyMultibase: string;
}
interface KeyAgreementKeyPair {
    id?: string;
    controller?: string;
    type: keyagreementType;
    publicKeyMultibase: string;
}
export default function HypersignEdvClient(params: {
    url: string;
    invocationKeyPair: InvocationKeyPair;
    keyagreementKeyPair: KeyAgreementKeyPair;
    keyResolver?: KeyResolver;
    shaHmacKey2020?: {
        id: string;
        type: string;
        key: string;
    };
}): HypersignEdvClientEd25519VerificationKey2020 | HypersignEdvClientEcdsaSecp256k1;
export {};
//# sourceMappingURL=hsEdvClient.d.ts.map