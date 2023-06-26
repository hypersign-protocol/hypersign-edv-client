/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
interface IKeyAgreementKey {
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    privateKeyMultibase?: string;
}
interface IEncryptionRequest {
    plainObject: object;
    recipients?: Array<any>;
    keyResolver?: Function;
    keyAgreementKey?: IKeyAgreementKey;
}
interface IDecryptionRequest {
    jwe: any;
    keyAgreementKey?: X25519KeyAgreementKey2020;
}
export default class HypersignCipher {
    private keyResolver;
    private cipher;
    private keyAgreementKey;
    constructor({ keyResolver, keyAgreementKey }: {
        keyResolver: Function;
        keyAgreementKey?: X25519KeyAgreementKey2020;
    });
    private _getX25519KeyAgreementKey;
    private _getX25519KeyAgreementResolver;
    private resolver;
    private _createDefaultRecipients;
    private _createParticipants;
    encryptObject({ plainObject, recipients, keyResolver, keyAgreementKey, }: IEncryptionRequest): Promise<object>;
    decryptObject({ jwe, keyAgreementKey }: IDecryptionRequest): Promise<object>;
}
export {};
//# sourceMappingURL=hsCipher.d.ts.map