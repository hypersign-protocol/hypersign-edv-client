/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import { IEncryptedDoc } from './hsDocumentDataModels';
export default class HypersignEncryptedDocument {
  encDoc: IEncryptedDoc;

  constructor({ data, metadata, jwe, id, sequence }: { data?: any; metadata?: any; jwe?: any; id?: string; sequence?: number }) {
    this.encDoc = {
      jwe: jwe ? jwe : undefined,
      data: data ? data : undefined,
      metadata: metadata ? metadata : undefined,
      id,
      sequence,
      timestamp: 0,
    };
  }

  get(): IEncryptedDoc {
    return this.encDoc;
  }
}
