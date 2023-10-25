import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
export interface IKeyAgreementKey {
    id: string;
    controller?: string;
    type: string;
    publicKeyMultibase?: string;
    privateKeyMultibase?: string;
}
export interface IRecipents {
    encrypted_key: string;
    header?: {
        kid: string;
        alg: string;
        apu: string;
        apv: string;
        epk: {
            kty: string;
            crv: string;
            x: string;
        };
    };
    keyId?: string;
}
export interface IEncryptionRequest {
    plainObject: object;
    recipients?: Array<IEncryptionRecipents>;
    keyResolver?: Function;
    keyAgreementKey?: IKeyAgreementKey;
}
export interface IJWE {
    protected: string;
    iv: string;
    ciphertext: string;
    tag: string;
    recipients: Array<IRecipents>;
}
export interface IDecryptionRequest {
    jwe: IJWE;
    keyAgreementKey?: X25519KeyAgreementKey2020;
}
export type KeyResolver = (key: {
    id: string;
}) => Promise<IKeyAgreementKey>;
export declare enum KeyAgreementKeyTypes {
    X25519KeyAgreementKey2020 = "X25519KeyAgreementKey2020",
    X25519KeyAgreementKeyEIP5630 = "X25519KeyAgreementKeyEIP5630"
}
export declare enum VerificationKeyTypes {
    Ed25519VerificationKey2020 = "Ed25519VerificationKey2020",
    EcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019",
    EcdsaSecp256k1RecoveryMethod2020 = "EcdsaSecp256k1RecoveryMethod2020"
}
export declare enum HmacKeyTypes {
    Sha256HmacKey2020 = "Sha256HmacKey2020"
}
export declare enum WalletTypes {
    Metamask = "metamask",
    Keplr = "keplr"
}
export interface IHmac {
    id: string;
    type: HmacKeyTypes;
}
export interface IDataVaultConfiguration {
    sequence: number;
    controller: string;
    invoker?: string;
    delegator?: string;
    referenceId?: string;
    keyAgreementKey: IKeyAgreementKey;
    hmac: IHmac;
    id: string;
    invokerVerificationMethodType?: VerificationKeyTypes;
}
export interface IEncryptedDoc {
    id?: string;
    sequence?: number;
    jwe?: IJWE;
    encryptedData?: IEncryptedData;
    timestamp?: number;
    metadata?: any;
    indexed?: Array<any>;
}
export interface IIndexAttribute {
    name: string;
    value: string;
}
export interface IHmac {
    id: string;
    type: HmacKeyTypes;
    key?: string;
}
export interface IIndexUnit {
    hmac: IHmac;
    attributes: Array<IIndexAttribute>;
}
export interface IEncryptedData {
    ciphertext: string;
    ephemPublicKey: string;
    nonce: string;
    recipients: Array<{
        encrypted_Key: IRecipents['encrypted_key'];
        keyId: IRecipents['keyId'];
    }>;
    version: string;
}
export interface IResponse {
    message: string;
    document: {
        id: string;
        encryptedData: IEncryptedData;
        indexd: Array<IIndexUnit>;
        jwe: IJWE;
    };
}
export interface IVerifcationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
    blockchainAccountId: string;
}
export interface signHTTPHeaders {
    controller: string;
    vermethodid: string;
    date: string;
}
export interface IEncryptionRecipents {
    id: string;
    type: KeyAgreementKeyTypes | string;
    publicKeyMultibase: string;
}
//# sourceMappingURL=Types.d.ts.map