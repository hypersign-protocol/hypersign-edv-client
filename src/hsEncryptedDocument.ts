/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import { IEncryptedDoc } from './hsDocumentDataModels';
export default class HypersignEncryptedDocument {
  encDoc: IEncryptedDoc;

  constructor({
    encryptedData,
    indexd,
    metadata,
    jwe,
    id,
    sequence,
  }: {
    encryptedData?: any;
    indexd?: Array<any>;
    metadata?: any;
    jwe?: any;
    id?: string;
    sequence?: number;
  }) {
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

  get(): IEncryptedDoc {
    return this.encDoc;
  }
}
