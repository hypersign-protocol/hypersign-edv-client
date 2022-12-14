export enum KeyAgreementKeyTypes {
  X25519KeyAgreementKey2020 = 'X25519KeyAgreementKey2020',
}

export enum VerificationKeyTypes {
  Ed25519VerificationKey2020 = 'Ed25519VerificationKey2020',
}

export enum HmacKeyTypes {
  Sha256HmacKey2020 = 'Sha256HmacKey2020',
}

export interface IKeyAgreementKey {
  id: string;
  type: KeyAgreementKeyTypes;
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
}
