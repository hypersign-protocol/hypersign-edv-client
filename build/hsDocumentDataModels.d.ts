/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
export interface IEncryptedDoc {
    id?: string;
    sequence?: number;
    jwe?: object;
    encryptedData?: object;
    timestamp?: number;
    metadata?: any;
    indexed?: Array<any>;
}
//# sourceMappingURL=hsDocumentDataModels.d.ts.map