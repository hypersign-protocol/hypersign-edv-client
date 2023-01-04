import { IEncryptedDoc } from './hsDocumentDataModels';
export default class HypersignEncryptedDocument {
  encDoc: IEncryptedDoc;

  constructor({ jwe, id, sequence }: { jwe: any; id?: string; sequence?: number }) {
    this.encDoc = {
      jwe: jwe,
      id,
      sequence,
      timestamp: 0,
    };
  }

  get(): IEncryptedDoc {
    return this.encDoc;
  }
}
