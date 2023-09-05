/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
export default class HypersignEncryptedDocument {
    constructor({ encryptedData, indexd, metadata, jwe, id, sequence, }) {
        this.encDoc = {
            jwe: jwe ? jwe : undefined,
            encryptedData: encryptedData ? encryptedData : undefined,
            metadata: metadata ? metadata : undefined,
            indexed: indexd ? indexd : undefined,
            id,
            sequence,
            timestamp: 0,
        };
    }
    get() {
        return this.encDoc;
    }
}
