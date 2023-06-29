/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { signHTTPHeaders } from './Types';
export default class HypersignZCapHttpSigner {
    private capabilityInvocationKey;
    constructor({ capabilityInvocationKey }: {
        capabilityInvocationKey: Ed25519VerificationKey2020;
    });
    signHTTP({ url, method, headers, encryptedObject, capabilityAction, }: {
        url: string;
        method: string;
        headers: signHTTPHeaders;
        encryptedObject: Object | undefined;
        capabilityAction: string;
    }): Promise<any>;
}
//# sourceMappingURL=hsZCapHttpSig.d.ts.map