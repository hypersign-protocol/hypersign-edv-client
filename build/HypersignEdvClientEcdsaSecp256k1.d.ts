import { IDataVaultConfiguration } from './hsEdvDataModels';
interface IVerifcationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
    blockchainAccountId: string;
}
interface KeyAgreementKeyPair {
    id: string;
    controller?: string;
    type: 'X25519KeyAgreementKeyEIP5630';
    publicKeyMultibase: string;
}
export default class HypersignEdvClientEcdsaSecp256k1 {
    private edvsUrl;
    private verificationMethod;
    private keyAgreement?;
    private encryptionPublicKeyBase64?;
    constructor({ url, verificationMethod, keyAgreement, }: {
        url?: string;
        verificationMethod: IVerifcationMethod;
        keyAgreement?: KeyAgreementKeyPair;
    });
    /**
     * Creates a new data vault for given configuration
     * @param edvId Optional edv id
     * @param invoker Optional invoker did
     * @param delegator Optional delegator did
     * @param referenceId Optional referenceId for data vault
     * @param controller controller did
     * @returns newly created data vault configuration
     */
    registerEdv(config: {
        edvId?: string;
        verificationMethod: IVerifcationMethod;
    }): Promise<IDataVaultConfiguration>;
    private canonicalizeJSON;
    private createCanonicalRequest;
    private signRequest;
    private sign;
    private signWithMetamask;
    private encryptDocument;
    private generateRandomString;
    private encrypt;
    /**
     * Inserts a new docs in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns updated document
     */
    insertDoc({ document, documentId, sequence, edvId, metadata, recipients }: {
        document: any;
        documentId: any;
        sequence: any;
        edvId: any;
        metadata: any;
        recipients: any;
    }): Promise<any>;
    /**
     * Updates doc in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns newly created document
     */
    updateDoc({ document, documentId, sequence, edvId, metadata, }: {
        document: any;
        documentId?: string;
        sequence?: number;
        edvId: string;
        metadata?: any;
    }): Promise<any>;
    /**
     * Fetchs docs related to a particular documentId
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns all documents (with sequences if not passed) for a documentId
     */
    fetchDoc({ documentId, edvId, sequence }: {
        documentId: string;
        edvId: string;
        sequence?: number;
    }): Promise<any>;
    decryptDocument({ encryptedDocument, recipient, }: {
        encryptedDocument: any;
        recipient: {
            id: string;
            type?: string;
        };
    }): Promise<any>;
    private decrypt;
    fetchAllDocs({ edvId, limit, page }: {
        edvId: any;
        limit: any;
        page: any;
    }): Promise<any>;
}
export {};
//# sourceMappingURL=HypersignEdvClientEcdsaSecp256k1.d.ts.map