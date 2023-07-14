/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import HypersignEdvClientEd25519VerificationKey2020 from './HypersignEdvClientEd25519VerificationKey2020';
import {  KeyResolver } from './Types';

import HypersignEdvClientEcdsaSecp256k1 from './HypersignEdvClientEcdsaSecp256k1';


enum invocationType {
  Ed25519VerificationKey2020 = 'Ed25519VerificationKey2020',
  HypersignEdvClientEcdsaSecp256k1 = 'HypersignEdvClientEcdsaSecp256k1',
}

enum keyagreementType {
  X25519KeyAgreementKey2020 = 'X25519KeyAgreementKey2020',
  X25519KeyAgreementKeyEIP5630 = 'X25519KeyAgreementKeyEIP5630',
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
}): HypersignEdvClientEd25519VerificationKey2020 | HypersignEdvClientEcdsaSecp256k1 {
  // : HypersignEdvClientEcdsaSecp256k1 | HypersignEdvClientEd25519VerificationKey2020

  if (!params.url) throw new Error('edvsUrl is required');
  if (!params.invocationKeyPair) throw new Error('InvocationKeyPair is required');
  if (!params.keyagreementKeyPair) throw new Error('KeyAgreementKeyPair is required');

  if (!params.invocationKeyPair.id) throw new Error('InvocationKeyPair.id is required');
  if (!params.invocationKeyPair.type) throw new Error('InvocationKeyPair.type is required');
  if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 && !params.invocationKeyPair.publicKeyMultibase)
    throw new Error('InvocationKeyPair.publicKeyMultibase is required');
  if (
    params.invocationKeyPair.type === invocationType.HypersignEdvClientEcdsaSecp256k1 &&
    !params.invocationKeyPair.blockchainAccountId
  )
    throw new Error('InvocationKeyPair.blockchainAccountId is required');

  if (!params.keyagreementKeyPair.id) throw new Error('KeyAgreementKeyPair.id is required');
  if (!params.keyagreementKeyPair.type) throw new Error('KeyAgreementKeyPair.type is required');
  if (
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020 &&
    !params.keyagreementKeyPair.publicKeyMultibase
  )
    throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
  if (
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKeyEIP5630 &&
    !params.keyagreementKeyPair.publicKeyMultibase
  )
    throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');

  if (
    params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 &&
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020
  ) {
    if (!params.keyResolver) throw new Error('keyResolver is required');
    return new HypersignEdvClientEd25519VerificationKey2020({
      url: params.url,
      ed25519VerificationKey2020: params.invocationKeyPair,
      x25519KeyAgreementKey2020: params.keyagreementKeyPair,
      keyResolver: params.keyResolver,
      shaHmacKey2020: params.shaHmacKey2020,
    }) as HypersignEdvClientEd25519VerificationKey2020;
  } else {
    return new HypersignEdvClientEcdsaSecp256k1({
      url: params.url,
      verificationMethod: params.invocationKeyPair,

      // Type Definition Inline
      keyAgreement: {
        id: params.keyagreementKeyPair.id,
        type: 'X25519KeyAgreementKeyEIP5630',
        publicKeyMultibase: params.keyagreementKeyPair.publicKeyMultibase,
        controller: params.keyagreementKeyPair.controller,
      },
    }) as HypersignEdvClientEcdsaSecp256k1;
  }
}
