"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
Object.defineProperty(exports, "__esModule", { value: true });
const http_signature_zcap_invoke_1 = require("@digitalbazaar/http-signature-zcap-invoke");
// Authorization Capabilities via HTTP signatures
class HypersignZCapHttpSigner {
    // capabilityInvocationKey: any;
    constructor({ capabilityInvocationKey }) {
        this.capabilityInvocationKey = capabilityInvocationKey;
    }
    // public async _getEd25519KeyPair(): Promise<Ed25519VerificationKey2020> {
    //   const keypairObj = await this.keyResolver();
    //   if (keypairObj.type != VerificationKeyTypes.Ed25519VerificationKey2020) {
    //     throw new Error('Unsupported singing key type: ' + keypairObj.type);
    //   }
    //   const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519VerificationKey2020.generate({ ...keypairObj });
    //   return ed25519KeyPair;
    // }
    async signHTTP({ url, method, headers, encryptedObject, capabilityAction, }) {
        const signedHeader = await (0, http_signature_zcap_invoke_1.signCapabilityInvocation)({
            url,
            method,
            headers,
            json: encryptedObject,
            invocationSigner: this.capabilityInvocationKey.signer(),
            capabilityAction,
        });
        return signedHeader;
    }
}
exports.default = HypersignZCapHttpSigner;
