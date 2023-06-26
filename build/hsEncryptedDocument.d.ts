/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { IEncryptedDoc } from './hsDocumentDataModels';
export default class HypersignEncryptedDocument {
    encDoc: IEncryptedDoc;
    constructor({ encryptedData, indexd, metadata, jwe, id, sequence, }: {
        encryptedData?: any;
        indexd?: Array<any>;
        metadata?: any;
        jwe?: any;
        id?: string;
        sequence?: number;
    });
    get(): IEncryptedDoc;
}
//# sourceMappingURL=hsEncryptedDocument.d.ts.map