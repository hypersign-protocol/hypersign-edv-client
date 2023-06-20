/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import { signCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-invoke';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { VerificationKeyTypes } from './hsEdvDataModels';

// Authorization Capabilities via HTTP signatures
export default class HypersignZCapHttpSigner {
  private capabilityInvocationKey: Ed25519VerificationKey2020;
  // capabilityInvocationKey: any;

  constructor({ capabilityInvocationKey }: { capabilityInvocationKey: Ed25519VerificationKey2020 }) {
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

  public async signHTTP({
    url,
    method,
    headers,
    encryptedObject,
    capabilityAction,
  }: {
    url: string;
    method: string;
    headers: object;
    encryptedObject: object | undefined;
    capabilityAction: string;
  }) {
    const signedHeader = await signCapabilityInvocation({
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
