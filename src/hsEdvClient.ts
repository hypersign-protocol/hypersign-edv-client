import Config from './config';
import Utils from './utils';
import HypersignEncryptedDocument from './hsEncryptedDocument';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { IDataVaultConfiguration, HmacKeyTypes, KeyAgreementKeyTypes } from './hsEdvDataModels';

import HypersignCipher from './hsCipher';
import HypersignZCapHttpSigner from './hsZCapHttpSig';
export default class HypersignEdvClient {
  private edvsUrl: string;
  private keyResolver: Function;
  private hsCipher: HypersignCipher;
  private hsHttpSigner: HypersignZCapHttpSigner;
  private keyAgreementKey: Ed25519VerificationKey2020;
  constructor({
    keyResolver,
    url,
    keyAgreementKey,
  }: {
    keyResolver: Function;
    url?: string;
    keyAgreementKey: Ed25519VerificationKey2020;
  }) {
    // optional parameters
    this.edvsUrl = Utils._sanitizeURL(url || Config.Defaults.edvsBaseURl);
    this.keyResolver = keyResolver;
    this.keyAgreementKey = keyAgreementKey;
    this.hsCipher = new HypersignCipher({ keyResolver: this.keyResolver, keyAgreementKey: this.keyAgreementKey });
    this.hsHttpSigner = new HypersignZCapHttpSigner({ keyAgreementKey: this.keyAgreementKey });
  }

  /**
   * {config.controller}
   *
   */
  public async registerEdv(config: {
    edvId?: string;
    invoker?: string;
    delegator?: string;
    referenceId?: string;
    controller: string;
    keyAgreementKey: { id: string; type: string };
    hmac: { id: string; type: string };
  }) {
    const edvConfig: IDataVaultConfiguration = {} as IDataVaultConfiguration;
    edvConfig.controller = config.controller;

    if (!KeyAgreementKeyTypes[config.keyAgreementKey.type]) {
      throw new Error('Unsupported keyagreement type: ' + config.keyAgreementKey.type);
    }

    if (!HmacKeyTypes[config.hmac.type]) {
      throw new Error('Unsupported hmac type: ' + config.hmac.type);
    }

    // Adding support for custom id
    if (config.edvId) {
      edvConfig.id = config.edvId;
    }

    edvConfig.keyAgreementKey = {
      id: config.keyAgreementKey.id,
      type: KeyAgreementKeyTypes[config.keyAgreementKey.type],
    };
    edvConfig.hmac = {
      id: config.hmac.id,
      type: HmacKeyTypes[config.hmac.type],
    };
    edvConfig.sequence = 0; // default values
    edvConfig.referenceId = 'primary'; // default values
    edvConfig.invoker = config.controller; // default values
    edvConfig.delegator = config.controller; // default values

    if (config.invoker) edvConfig.invoker = config.invoker;
    if (config.referenceId) edvConfig.referenceId = config.referenceId;
    if (config.delegator) edvConfig.delegator = config.delegator;

    const edvRegisterURl = this.edvsUrl + Config.APIs.edvAPI;

    const resp: IDataVaultConfiguration = await Utils._makeAPICall({
      url: edvRegisterURl,
      method: 'POST',
      body: edvConfig,
    });

    // attaching the newly created edv id
    edvConfig.id = resp.id;
    return edvConfig;
  }

  public async getEdvConfig(edvId: string) {
    throw new Error('Method not implemented');
  }

  public async insertDoc({
    document,
    documentId,
    sequence,
    edvId,
  }: {
    document: any;
    documentId?: string;
    sequence?: number;
    edvId: string;
  }) {
    // encrypt the document
    const jwe = await this.hsCipher.encryptObject({
      plainObject: document,
    });
    const hsEncDoc = new HypersignEncryptedDocument({ jwe, id: documentId, sequence });

    // form the http request header by signing the header
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.keyAgreementKey.controller,
      vermethodid: this.keyAgreementKey.id,
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

  public async updateDoc({
    document,
    documentId,
    sequence,
    edvId,
  }: {
    document: any;
    documentId?: string;
    sequence?: number;
    edvId: string;
  }) {
    // encrypt the document
    const jwe = await this.hsCipher.encryptObject({
      plainObject: document,
    });
    const hsEncDoc = new HypersignEncryptedDocument({ jwe, id: documentId, sequence });

    // form the http request header by signing the header
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';
    const headers = {
      // digest signature
      // authorization header,
      controller: this.keyAgreementKey.controller,
      vermethodid: this.keyAgreementKey.id,
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

  public async fetchAllDocs() {
    throw new Error('Method not implemented');
  }

  public async fetchDoc({ documentId }) {
    console.log({ documentId });

    throw new Error('Method not implemented');
  }

  public async deleteDoc({ documentId }) {
    console.log({ documentId });

    throw new Error('Method not implemented');
  }
}
