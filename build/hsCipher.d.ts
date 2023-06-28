/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { KeyResolver, IEncryptionRequest, IJWE, IDecryptionRequest } from './Types';
export default class HypersignCipher {
    private keyResolver;
    private cipher;
    private keyAgreementKey;
    constructor({ keyResolver, keyAgreementKey }: {
        keyResolver: KeyResolver;
        keyAgreementKey?: X25519KeyAgreementKey2020;
    });
    private _getX25519KeyAgreementKey;
    private _getX25519KeyAgreementResolver;
    private resolver;
    private _createDefaultRecipients;
    private _createParticipants;
    encryptObject({ plainObject, recipients, keyResolver, keyAgreementKey, }: IEncryptionRequest): Promise<IJWE>;
    decryptObject({ jwe, keyAgreementKey }: IDecryptionRequest): Promise<object>;
}
//# sourceMappingURL=hsCipher.d.ts.map