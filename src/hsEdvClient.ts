/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */

import Config from './config';
import Utils from './utils';
import HypersignEncryptedDocument from './hsEncryptedDocument';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
import { IDataVaultConfiguration, HmacKeyTypes, KeyAgreementKeyTypes } from './hsEdvDataModels';

import HypersignCipher from './hsCipher';
import HypersignZCapHttpSigner from './hsZCapHttpSig';
import HypersignEdvClientEcdsaSecp256k1 from './HypersignEdvClientEcdsaSecp256k1';
import Hmac from './Hmac';
import { IndexHelper } from './IndexHelper';
export class HypersignEdvClientEd25519VerificationKey2020 {
  private edvsUrl: string;
  private keyResolver: Function;
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
    keyResolver: Function;
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
    this.edvsUrl = Utils._sanitizeURL(url || Config.Defaults.edvsBaseURl);
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
    keyAgreementKey?: { id: string; type: string };
    hmac?: { id: string; type: string };
  }) {
    const edvConfig: IDataVaultConfiguration = {} as IDataVaultConfiguration;
    edvConfig.controller = config.controller;

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
    document: any;
    documentId?: string;
    sequence?: number;
    metadata?: any;
    edvId: string;
    recipients?: any;
    indexs?: Array<{ index: String; unique: boolean }>;
  }) {
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

    const jwe = await this.hsCipher.encryptObject({
      plainObject: document,
      recipients,
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
  }) {
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
      console.log('finalIndex', finalIndex);

      console.log('finalIndexUpadte', await indexDoc.updateEntry({ doc: document, hmac }));
    }
    const jwe = await this.hsCipher.encryptObject({
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
  public async fetchDoc({ documentId, edvId, sequence }: { documentId: string; edvId: string; sequence?: number }) {
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document/' + documentId;

    //// TODO:  need to figure out how will it work in read capability
    /// CAUTION:::  for time being, I have skipped signature verification wicich is security vulnerabilities

    // // encrypt the document
    // const jwe = await this.hsCipher.encryptObject({
    //   plainObject: { foo: 'bar' },
    // });
    // const hsEncDoc = new HypersignEncryptedDocument({ jwe, id: documentId, sequence });

    // const headers = {
    //   // digest signature
    //   // authorization header,
    //   controller: this.ed25519VerificationKey2020.controller,
    //   vermethodid: this.ed25519VerificationKey2020.id,
    //   date: new Date().toUTCString(),
    // };
    // const method = 'GET';
    // const signedHeader = await this.hsHttpSigner.signHTTP({
    //   url: edvDocAddUrl,
    //   method,
    //   headers,
    //   encryptedObject: hsEncDoc.get(), // TODO: not sure why its not working with empty object. for GET request what data does it expect??
    //   capabilityAction: 'read',
    // });

    // make the call to store

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

  public async fetchAllDocs({ edvId, limit, page }) {
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

  public async deleteDoc({ documentId }) {
    throw new Error('Method not implemented');
  }
}

enum invocationType {
  Ed25519VerificationKey2020 = 'Ed25519VerificationKey2020',
  HypersignEdvClientEcdsaSecp256k1 = 'HypersignEdvClientEcdsaSecp256k1',
}

enum keyagreementType {
  X25519KeyAgreementKey2020 = 'X25519KeyAgreementKey2020',
  X25519KeyAgreementKeyEIP5630 = 'X25519KeyAgreementKeyEIP5630',
}
interface InvocationKeyPair {
  id: string;
  type: invocationType;
  controller: string;
  publicKeyMultibase: string;
  blockchainAccountId: string;
  privateKeyMultibase: string;
}

interface KeyAgreementKeyPair {
  id?: string;
  controller?: string;
  type: keyagreementType;
  publicKeyMultibase: string;
}

export default function HypersignEdvClient(params: {
  url: string;
  invocationKeyPair: InvocationKeyPair;
  keyagreementKeyPair: KeyAgreementKeyPair;
  keyResolver?: Function;
  shaHmacKey2020?: {
    id: string;
    type: string;
    key: string;
  };
}): any {
  // : HypersignEdvClientEcdsaSecp256k1 | HypersignEdvClientEd25519VerificationKey2020

  if (!params.url) throw new Error('edvsUrl is required');
  if (!params.invocationKeyPair) throw new Error('InvocationKeyPair is required');
  if (!params.keyagreementKeyPair) throw new Error('KeyAgreementKeyPair is required');

  if (!params.invocationKeyPair.id) throw new Error('InvocationKeyPair.id is required');
  if (!params.invocationKeyPair.type) throw new Error('InvocationKeyPair.type is required');
  if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 && !params.invocationKeyPair.publicKeyMultibase)
    throw new Error('InvocationKeyPair.publicKeyMultibase is required');
  if (
    params.invocationKeyPair.type === invocationType.HypersignEdvClientEcdsaSecp256k1 &&
    !params.invocationKeyPair.blockchainAccountId
  )
    throw new Error('InvocationKeyPair.blockchainAccountId is required');

  if (!params.keyagreementKeyPair.id) throw new Error('KeyAgreementKeyPair.id is required');
  if (!params.keyagreementKeyPair.type) throw new Error('KeyAgreementKeyPair.type is required');
  if (
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020 &&
    !params.keyagreementKeyPair.publicKeyMultibase
  )
    throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
  if (
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKeyEIP5630 &&
    !params.keyagreementKeyPair.publicKeyMultibase
  )
    throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');

  if (
    params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 &&
    params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020
  ) {
    if (!params.keyResolver) throw new Error('keyResolver is required');
    return new HypersignEdvClientEd25519VerificationKey2020({
      url: params.url,
      ed25519VerificationKey2020: params.invocationKeyPair,
      x25519KeyAgreementKey2020: params.keyagreementKeyPair,
      keyResolver: params.keyResolver,
      shaHmacKey2020: params.shaHmacKey2020,
    });
  } else {
    return new HypersignEdvClientEcdsaSecp256k1({
      url: params.url,
      verificationMethod: params.invocationKeyPair,

      // Type Definition Inline
      keyAgreement: {
        id: params.keyagreementKeyPair.id,
        type: 'X25519KeyAgreementKeyEIP5630',
        publicKeyMultibase: params.keyagreementKeyPair.publicKeyMultibase,
        controller: params.keyagreementKeyPair.controller,
      },
    });
  }
}
