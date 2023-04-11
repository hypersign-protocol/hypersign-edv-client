/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

export enum KeyAgreementKeyTypes {
  X25519KeyAgreementKey2020 = 'X25519KeyAgreementKey2020',
}

export enum VerificationKeyTypes {
  Ed25519VerificationKey2020 = 'Ed25519VerificationKey2020',
  EcdsaSecp256k1VerificationKey2019 = 'EcdsaSecp256k1VerificationKey2019',
  EcdsaSecp256k1RecoveryMethod2020 = 'EcdsaSecp256k1RecoveryMethod2020',
}

export enum HmacKeyTypes {
  Sha256HmacKey2020 = 'Sha256HmacKey2020',
}

export interface IKeyAgreementKey {
  id: string;
  type: KeyAgreementKeyTypes;
}

export enum WalletTypes {
  Metamask = 'metamask',
  Keplr = 'keplr',
}

export interface IHmac {
  id: string;
  type: HmacKeyTypes;
}

export interface IDataVaultConfiguration {
  sequence: number; // required
  controller: string; // required
  invoker?: string; // optional
  delegator?: string; // optional
  referenceId?: string; // optional
  keyAgreementKey: IKeyAgreementKey; // required
  hmac: IHmac; // required
  id: string;
  invokerVerificationMethodType?: VerificationKeyTypes;
}
