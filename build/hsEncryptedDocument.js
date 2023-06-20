"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
Object.defineProperty(exports, "__esModule", { value: true });
class HypersignEncryptedDocument {
    constructor({ data, indexd, metadata, jwe, id, sequence, }) {
        this.encDoc = {
            jwe: jwe ? jwe : undefined,
            data: data ? data : undefined,
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
exports.default = HypersignEncryptedDocument;
