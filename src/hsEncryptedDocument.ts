import { IEncryptedDoc } from './hsDocumentDataModels';
export default class HypersignEncryptedDocument {
  encDoc: IEncryptedDoc;

  constructor({ jwe }) {
    this.encDoc = {
      jwe: jwe,
      id: '',
      sequence: 0,
      timestamp: 0,
    };
  }

  get(): IEncryptedDoc {
    return this.encDoc;
  }
}
