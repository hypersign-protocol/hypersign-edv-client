/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
import { IEncryptedData, IEncryptedDoc, IIndexUnit, IJWE } from './Types';
export default class HypersignEncryptedDocument {
    encDoc: IEncryptedDoc;
    constructor({ encryptedData, indexd, metadata, jwe, id, sequence, }: {
        encryptedData?: IEncryptedData;
        indexd?: Array<IIndexUnit>;
        metadata?: any;
        jwe?: IJWE;
        id?: string;
        sequence?: number;
    });
    get(): IEncryptedDoc;
}
//# sourceMappingURL=hsEncryptedDocument.d.ts.map