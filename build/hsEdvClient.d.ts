/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { IDataVaultConfiguration, IResponse, IEncryptionRecipents } from './Types';
import { IKeyAgreementKey, KeyResolver } from './Types';
import HypersignEdvClientEcdsaSecp256k1 from './HypersignEdvClientEcdsaSecp256k1';
export declare class HypersignEdvClientEd25519VerificationKey2020 {
    private edvsUrl;
    private keyResolver;
    private hsCipher;
    private hsHttpSigner;
    private ed25519VerificationKey2020;
    private x25519KeyAgreementKey2020;
    private shaHmacKey2020;
    constructor({ keyResolver, url, ed25519VerificationKey2020, x25519KeyAgreementKey2020, shaHmacKey2020, }: {
        keyResolver: KeyResolver;
        url?: string;
        ed25519VerificationKey2020: Ed25519VerificationKey2020;
        x25519KeyAgreementKey2020: X25519KeyAgreementKey2020;
        shaHmacKey2020?: {
            id: string;
            type: string;
            key: string;
        };
    });
    /**
     * Creates a new data vault for given configuration
     * @param edvId Optional edv id
     * @param invoker Optional invoker did
     * @param delegator Optional delegator did
     * @param referenceId Optional referenceId for data vault
     * @param controller controller did
     * @param keyAgreementKey keyAgreementKey
     * @param hmac hmac
     * @returns newly created data vault configuration
     */
    registerEdv(config: {
        edvId?: string;
        invoker?: string;
        delegator?: string;
        referenceId?: string;
        controller: string;
        keyAgreementKey?: IKeyAgreementKey;
        hmac?: {
            id: string;
            type: string;
            key?: string;
        };
    }): Promise<IDataVaultConfiguration>;
    /**
     * Inserts a new docs in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns updated document
     */
    insertDoc({ document, metadata, documentId, sequence, edvId, recipients, indexs, }: {
        document: object;
        documentId?: string;
        sequence?: number;
        metadata?: object;
        edvId: string;
        recipients?: Array<IEncryptionRecipents>;
        indexs?: Array<{
            index: String;
            unique: boolean;
        }>;
    }): Promise<IResponse>;
    /**
     * Updates doc in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns newly created document
     */
    updateDoc({ document, documentId, sequence, edvId, metadata, indexs, }: {
        document: any;
        documentId?: string;
        sequence?: number;
        edvId: string;
        metadata?: any;
        indexs?: Array<{
            index: String;
            unique: boolean;
        }>;
    }): Promise<IResponse>;
    /**
     * Fetchs docs related to a particular documentId
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns all documents (with sequences if not passed) for a documentId
     */
    fetchDoc({ documentId, edvId, sequence, }: {
        documentId: string;
        edvId: string;
        sequence?: number;
    }): Promise<IResponse>;
    getEdvConfig(edvId: string): Promise<void>;
    fetchAllDocs({ edvId, limit, page }: {
        edvId: any;
        limit: any;
        page: any;
    }): Promise<IResponse[]>;
    Query({ edvId, equals, has, }: {
        edvId: string;
        equals?: {
            [key: string]: string;
        };
        has?: Array<string>;
    }): Promise<any>;
    deleteDoc({ documentId }: {
        documentId: any;
    }): Promise<void>;
}
declare enum invocationType {
    Ed25519VerificationKey2020 = "Ed25519VerificationKey2020",
    HypersignEdvClientEcdsaSecp256k1 = "HypersignEdvClientEcdsaSecp256k1"
}
declare enum keyagreementType {
    X25519KeyAgreementKey2020 = "X25519KeyAgreementKey2020",
    X25519KeyAgreementKeyEIP5630 = "X25519KeyAgreementKeyEIP5630"
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
}): HypersignEdvClientEd25519VerificationKey2020 | HypersignEdvClientEcdsaSecp256k1;
export {};
//# sourceMappingURL=hsEdvClient.d.ts.map