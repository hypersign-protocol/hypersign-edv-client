import Config from './config';
import Utils from './utils';
import HypersignEncryptedDocument from './hsEncryptedDocument';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import {
  IDataVaultConfiguration,
  HmacKeyTypes,
  KeyAgreementKeyTypes,
  IRecipents,
  IJWE,
  IIndexUnit,
  IEncryptedData,
  IResponse,
  IEncryptionRecipents,
} from './Types';

import HypersignCipher from './hsCipher';
import { IKeyAgreementKey, KeyResolver } from './Types';
import HypersignZCapHttpSigner from './hsZCapHttpSig';
import Hmac from './Hmac';
import { IndexHelper } from './IndexHelper';
export default class HypersignEdvClientEd25519VerificationKey2020 {
  private edvsUrl: URL;
  private keyResolver: KeyResolver;
  private hsCipher: HypersignCipher;
  private hsHttpSigner: HypersignZCapHttpSigner;
  private ed25519VerificationKey2020: Ed25519VerificationKey2020;
  private x25519KeyAgreementKey2020: X25519KeyAgreementKey2020;
  private shaHmacKey2020: {
    id: string;
    key?: string;
    type: string;
  };
  constructor({
    keyResolver,
    url,
    ed25519VerificationKey2020,
    x25519KeyAgreementKey2020,
    shaHmacKey2020,
  }: {
    keyResolver: KeyResolver;
    url?: string;
    ed25519VerificationKey2020: Ed25519VerificationKey2020;
    x25519KeyAgreementKey2020: X25519KeyAgreementKey2020;
    shaHmacKey2020?: {
      id: string;
      type: string;
      key: string;
    };
  }) {
    // optional parameters
    this.edvsUrl = new URL(Utils._sanitizeURL(url || Config.Defaults.edvsBaseURl));
    if (!this.edvsUrl.pathname.endsWith('/')) {
      this.edvsUrl.pathname += '/';
    } else {
      this.edvsUrl.pathname = this.edvsUrl.pathname;
    }
    this.keyResolver = keyResolver;
    this.ed25519VerificationKey2020 = ed25519VerificationKey2020;
    this.x25519KeyAgreementKey2020 = x25519KeyAgreementKey2020;
    this.hsCipher = new HypersignCipher({ keyResolver: this.keyResolver, keyAgreementKey: x25519KeyAgreementKey2020 });
    this.shaHmacKey2020 = shaHmacKey2020
      ? shaHmacKey2020
      : {
          id: ed25519VerificationKey2020.id,
          type: HmacKeyTypes.Sha256HmacKey2020,
          key: ed25519VerificationKey2020.privateKeyMultibase,
        };

    // always ed25519VerificationKey2020
    this.hsHttpSigner = new HypersignZCapHttpSigner({ capabilityInvocationKey: this.ed25519VerificationKey2020 });
  }

  /**
   * Creates a new data vault for given configuration
   * @param edvId Optional edv id
   * @param invoker Optional invoker did
   * @param delegator Optional delegator did
   * @param referenceId Optional referenceId for data vault
   * @param controller controller did
   * @param keyAgreementKey keyAgreementKey
   * @param hmac hmac
   * @returns newly created data vault configuration
   */
  public async registerEdv(config: {
    edvId?: string;
    invoker?: string;
    delegator?: string;
    referenceId?: string;
    controller: string;
    keyAgreementKey?: IKeyAgreementKey;
    hmac?: { id: string; type: string; key?: string };
  }) {
    const edvConfig: IDataVaultConfiguration = {} as IDataVaultConfiguration;
    edvConfig.controller = config.controller;
    if (config.edvId) {
      edvConfig.id = config.edvId;
    }
    if (config.keyAgreementKey && !KeyAgreementKeyTypes[config.keyAgreementKey.type]) {
      throw new Error('Unsupported keyagreement type: ' + config.keyAgreementKey.type);
    }

    if (config.hmac && !HmacKeyTypes[config.hmac.type]) {
      throw new Error('Unsupported hmac type: ' + config.hmac.type);
    }

    // Adding support for custom id
    if (config.edvId) {
      edvConfig.id = config.edvId;
    }

    if (config.keyAgreementKey && config.hmac) {
      edvConfig.keyAgreementKey = {
        id: config.keyAgreementKey.id,
        type: KeyAgreementKeyTypes[config.keyAgreementKey.type],
      };
      edvConfig.hmac = {
        id: config.hmac.id,
        type: HmacKeyTypes[config.hmac.type],
      };
    } else {
      edvConfig.keyAgreementKey = {
        id: this.x25519KeyAgreementKey2020.id,
        type: KeyAgreementKeyTypes[this.x25519KeyAgreementKey2020.type],
      };
      edvConfig.hmac = {
        id: this.shaHmacKey2020.id,
        type: HmacKeyTypes[this.shaHmacKey2020.type],
      };
    }

    edvConfig.sequence = 0; // default values
    edvConfig.referenceId = 'primary'; // default values
    edvConfig.invoker = config.controller; // default values
    edvConfig.delegator = config.controller; // default values

    if (config.invoker) edvConfig.invoker = config.invoker;
    if (config.referenceId) edvConfig.referenceId = config.referenceId;
    if (config.delegator) edvConfig.delegator = config.delegator;

    const edvRegisterURl = this.edvsUrl + Config.APIs.edvAPI;

    const method = 'POST';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvRegisterURl,
      method,
      headers,
      encryptedObject: edvConfig,
      capabilityAction: 'write',
    });

    const resp: IDataVaultConfiguration = await Utils._makeAPICall({
      url: edvRegisterURl,
      method: 'POST',
      body: edvConfig,
      headers: signedHeader,
    });

    // attaching the newly created edv id
    edvConfig.id = resp.id;
    return edvConfig;
  }

  /**
   * Inserts a new docs in the data vault
   * @param document doc to be updated in plain text
   * @param documentId Id of the document
   * @param edvId Id of the data vault
   * @param sequence Optional sequence number, default is 0
   * @returns updated document
   */
  public async insertDoc({
    document,
    metadata,
    documentId,
    sequence,
    edvId,
    recipients,
    indexs,
  }: {
    document: object;
    documentId?: string;
    sequence?: number;
    metadata?: object;
    edvId: string;
    recipients?: Array<IEncryptionRecipents>;
    indexs?: Array<{ index: String; unique: boolean }>;
  }): Promise<IResponse> {
    // encrypt the document
    let finalIndex;
    if (indexs) {
      const hmac = await Hmac.create({
        key: this.shaHmacKey2020.key,
        id: this.shaHmacKey2020.id,
      });

      const indexDoc = new IndexHelper();

      indexs.forEach(async (attr) => {
        indexDoc.ensureIndex({
          attribute: attr.index,
          unique: attr.unique,
          hmac,
        });
      });

      finalIndex = await indexDoc.createEntry({ doc: document, hmac });
    }

    const { jwe, encryptedData } = await this.hsCipher.encryptObject({
      plainObject: document,
      recipients,
    });

    const hsEncDoc = new HypersignEncryptedDocument({
      jwe,
      encryptedData,
      indexd: [finalIndex],
      id: documentId,
      metadata,
      sequence,
    });

    // form the http request header by signing the header
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const method = 'POST';
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvDocAddUrl,
      method,
      headers,
      encryptedObject: hsEncDoc.get(),
      capabilityAction: 'write',
    });

    // make the call to store
    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method,
      body: hsEncDoc.get(),
      headers: signedHeader,
    });

    return resp;
  }

  /**
   * Updates doc in the data vault
   * @param document doc to be updated in plain text
   * @param documentId Id of the document
   * @param edvId Id of the data vault
   * @param sequence Optional sequence number, default is 0
   * @returns newly created document
   */
  public async updateDoc({
    document,
    documentId,
    sequence,
    edvId,
    metadata,
    indexs,
  }: {
    document: any;
    documentId?: string;
    sequence?: number;
    edvId: string;
    metadata?: any;
    indexs?: Array<{ index: String; unique: boolean }>;
  }): Promise<IResponse> {
    // encrypt the document

    let finalIndex;
    if (indexs) {
      const hmac = await Hmac.create({
        key: this.shaHmacKey2020.key,
        id: this.shaHmacKey2020.id,
      });

      const indexDoc = new IndexHelper();

      indexs.forEach(async (attr) => {
        indexDoc.ensureIndex({
          attribute: attr.index,
          unique: attr.unique,
          hmac,
        });
      });

      finalIndex = await indexDoc.createEntry({ doc: document, hmac });
    }
    const { jwe } = await this.hsCipher.encryptObject({
      plainObject: document,
    });
    const hsEncDoc = new HypersignEncryptedDocument({ jwe, indexd: [finalIndex], id: documentId, metadata, sequence });

    // form the http request header by signing the header
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const method = 'PUT';
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvDocAddUrl,
      method,
      headers,
      encryptedObject: hsEncDoc.get(),
      capabilityAction: 'write',
    });

    // make the call to store
    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method,
      body: hsEncDoc.get(),
      headers: signedHeader,
    });

    return resp;
  }

  /**
   * Fetchs docs related to a particular documentId
   * @param documentId Id of the document
   * @param edvId Id of the data vault
   * @param sequence Optional sequence number, default is 0
   * @returns all documents (with sequences if not passed) for a documentId
   */
  public async fetchDoc({
    documentId,
    edvId,
    sequence,
  }: {
    documentId: string;
    edvId: string;
    sequence?: number;
  }): Promise<IResponse> {
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document/' + documentId;

    const method = 'GET';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvDocAddUrl,
      method,
      headers,
      encryptedObject: undefined,
      capabilityAction: 'read',
    });

    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'GET',
      headers: signedHeader,
    });

    return resp;
  }

  public async getEdvConfig(edvId: string) {
    throw new Error('Method not implemented');
  }

  public async fetchAllDocs({ edvId, limit, page }): Promise<IResponse[]> {
    if (!limit) limit = 10;
    if (!page) page = 1;

    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/documents' + '?limit=' + limit + '&page=' + page;
    const method = 'GET';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvDocAddUrl,
      method,
      headers,
      encryptedObject: undefined,
      capabilityAction: 'read',
    });
    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'GET',
      headers: signedHeader,
    });

    return resp;
  }

  public async Query({
    edvId,
    equals,
    has,
  }: {
    edvId: string;
    equals?: {
      [key: string]: string;
    };
    has?: Array<string>;
  }) {
    const hmac = await Hmac.create({
      key: this.shaHmacKey2020.key,
      id: this.shaHmacKey2020.id,
    });
    if (equals == undefined && has == undefined) throw new Error('Either equals or has should be passed');
    if (equals && has) throw new Error('Either equals or has should be passed');

    const indexDoc = new IndexHelper();
    const query = await indexDoc.buildQuery({
      hmac,
      equals: equals ? equals : undefined,
      has: has ? has : undefined,
    });

    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/query';
    const method = 'POST';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.ed25519VerificationKey2020.controller,
      vermethodid: this.ed25519VerificationKey2020.id,
      date: new Date().toUTCString(),
    };
    const signedHeader = await this.hsHttpSigner.signHTTP({
      url: edvDocAddUrl,
      method,
      headers,
      encryptedObject: query,
      capabilityAction: 'write',
    });

    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'POST',
      headers: signedHeader,
      body: query,
    });

    return resp;
  }

  public async deleteDoc({ documentId }) {
    throw new Error('Method not implemented');
  }

  public async decryptObject({ jwe, keyAgreementKey }) {
    return this.hsCipher.decryptObject({
      jwe,
      keyAgreementKey,
    });
  }
}
