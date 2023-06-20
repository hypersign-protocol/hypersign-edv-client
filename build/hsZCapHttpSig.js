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
    signHTTP({ url, method, headers, encryptedObject, capabilityAction, }) {
        return __awaiter(this, void 0, void 0, function* () {
            const signedHeader = yield (0, http_signature_zcap_invoke_1.signCapabilityInvocation)({
                url,
                method,
                headers,
                json: encryptedObject,
                invocationSigner: this.capabilityInvocationKey.signer(),
                capabilityAction,
            });
            return signedHeader;
        });
    }
}
exports.default = HypersignZCapHttpSigner;
