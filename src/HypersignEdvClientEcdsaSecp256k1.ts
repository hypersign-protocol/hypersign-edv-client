/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Pratap Mridha (Github @pratap2018)
 */

import Config from './config';
import Utils from './utils';
import HypersignEncryptedDocument from './hsEncryptedDocument';
import { IDataVaultConfiguration, VerificationKeyTypes } from './hsEdvDataModels';
import web3 from 'web3';

const ethUtil = require('ethereumjs-util');
const sigUtil = require('@metamask/eth-sig-util');

// Path: src/hsEdvClient.ts
import crypto from 'crypto';

import { WalletTypes } from './hsEdvDataModels';

interface IVerifcationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
  blockchainAccountId: string;
}

// edv client using metamask

export default class HypersignEdvClientEcdsaSecp256k1 {
  private edvsUrl: string;
  private verificationMethod: IVerifcationMethod;

  constructor({ url, verificationMethod }: { url?: string; verificationMethod: IVerifcationMethod }) {
    this.edvsUrl = Utils._sanitizeURL(url || Config.Defaults.edvsBaseURl);
    if (
      verificationMethod.type !== 'EcdsaSecp256k1VerificationKey2019' &&
      verificationMethod.type !== 'EcdsaSecp256k1RecoveryMethod2020'
    ) {
      throw new Error('Verification method not supported');
    }
    this.verificationMethod = verificationMethod;
  }

  /**
   * Creates a new data vault for given configuration
   * @param edvId Optional edv id
   * @param invoker Optional invoker did
   * @param delegator Optional delegator did
   * @param referenceId Optional referenceId for data vault
   * @param controller controller did
   * @returns newly created data vault configuration
   */

  public async registerEdv(config: { edvId?: string; verificationMethod: IVerifcationMethod }) {
    this.verificationMethod = this.verificationMethod;
    const edvConfig: IDataVaultConfiguration = {} as IDataVaultConfiguration;
    edvConfig.controller = config.verificationMethod.controller;
    // Adding support for custom id
    if (config.edvId) {
      edvConfig.id = config.edvId;
    }

    edvConfig.sequence = 0; // default values
    edvConfig.referenceId = 'primary'; // default values
    edvConfig.invoker = config.verificationMethod.id; // default values
    edvConfig.delegator = config.verificationMethod.id; // default values

    if (this.verificationMethod.blockchainAccountId.includes('eip155:')) {
      edvConfig.invokerVerificationMethodType = VerificationKeyTypes.EcdsaSecp256k1RecoveryMethod2020;
    } else if (this.verificationMethod.blockchainAccountId.includes('cosmos:')) {
      edvConfig.invokerVerificationMethodType = VerificationKeyTypes.EcdsaSecp256k1VerificationKey2019;
    } else {
      throw new Error('Verification method not supported');
    }

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

  private canonicalizeJSON(json) {
    // Step 1: Convert to JSON string
    const jsonString = JSON.stringify(json);

    // Step 2: Normalize line endings to CRLF
    const crlfString = jsonString.replace(/\r?\n/g, '\r\n');

    // Step 3: Remove all whitespace between tokens
    const compactString = crlfString.replace(/\s+/g, '');

    // Step 4: Sort the keys in every object in the JSON structure
    const sortedJson = JSON.parse(crlfString, (key, value) => {
      if (Array.isArray(value)) {
        return value.map((val) => {
          if (typeof val === 'object' && val !== null) {
            return Object.keys(val)
              .sort()
              .reduce((acc, curr) => {
                acc[curr] = val[curr];
                return acc;
              }, {});
          } else {
            return val;
          }
        });
      } else if (typeof value === 'object' && value !== null) {
        return Object.keys(value)
          .sort()
          .reduce((acc, curr) => {
            acc[curr] = value[curr];
            return acc;
          }, {});
      } else {
        return value;
      }
    });

    // Step 5: Convert back to string
    const sortedString = JSON.stringify(sortedJson);

    return sortedString;
  }

  private async createCanonicalRequest({ url, method, query, headers, body }) {
    let action = 'read';
    if (method.toUpperCase() === 'POST' || method.toUpperCase() === 'PUT' || method.toUpperCase() === 'DELETE') {
      action = 'write';
    }

    if (typeof body == 'object') {
      body = this.canonicalizeJSON(body);
    }

    let payloadHash;
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      payloadHash = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(body || '')).then((hash) => {
        const hashArray = Array.from(new Uint8Array(hash));
        const base64 = btoa(String.fromCharCode(...hashArray));
        return base64;
      });
    } else {
      payloadHash = crypto
        .createHash('sha256')
        .update(body || '')
        .digest('base64');
      payloadHash = payloadHash.toString('base64');
    }
    headers['digest'] = `SHA-256=${payloadHash}`;

    const urlObj = new URL(url);
    headers['host'] = urlObj.host;
    query = urlObj.searchParams;
    const path = urlObj.pathname;
    headers['request-target'] = urlObj.href;

    headers['capability-invocation'] = `zcap id="urn:zcap:root:${encodeURI(headers['request-target'])}",action="${action}"`;

    const canonicalURI = encodeURIComponent(path);
    let canonicalQueryString = '';
    if (query) {
      const entries = query.entries();
      const result = {};
      for (const [key, value] of entries) {
        // each 'entry' is a [key, value] tupple
        result[key] = value;
      }
      canonicalQueryString = Object.keys(result)
        .sort()
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(result[key])}`)
        .join('&');
    }
    const canonicalHeaders = Object.keys(headers)
      .map((key) => `${key.toLowerCase()}:${headers[key].trim().replace(/\s+/g, ' ')}`)
      .sort()
      .join('\n');

    const signedHeaders = Object.keys(headers)

      .map((key) => {
        let k = key.toLowerCase();
        switch (k) {
          case 'keyid':
            return 'keyId';
          case 'created':
            return '(created)';
          case 'expires':
            return '(expires)';
          case 'request-target':
            return '(request-target)';
          default:
            return k;
        }
      })
      .sort()
      .join(', ');

    const canonicalRequest = [method.toUpperCase(), canonicalURI, canonicalQueryString, canonicalHeaders, '', signedHeaders].join(
      '\n',
    );

    return { canonicalRequest, canonicalHeaders, signedHeaders, payloadHash };
  }

  private async signRequest({ url, method, query, headers, body, keyId }) {
    const { canonicalRequest, canonicalHeaders, signedHeaders, payloadHash } = await this.createCanonicalRequest({
      url,
      method,
      query,
      headers,
      body,
    });
    const publicKeyOrAddress = keyId.split('#')[1];
    let walletType;
    let walletAddress = publicKeyOrAddress.split(':')[2];
    if (publicKeyOrAddress.includes('eip155:')) {
      walletType = WalletTypes.Metamask;
    } else {
      walletType = WalletTypes.Keplr;
    }
    const signature = await this.sign(canonicalRequest, walletAddress, walletType);
    return { signature, canonicalHeaders, signedHeaders, payloadHash };
  }
  private async sign(canonicalRequest, walletAddress, walletType) {
    let signature;
    switch (walletType) {
      case WalletTypes.Metamask:
        signature = await this.signWithMetamask(canonicalRequest, walletAddress);
        break;
      case WalletTypes.Keplr:
        throw new Error('Wallet type not supported');

        //signature = await this.signWithKeplr(canonicalRequest,walletAddress)
        break;
      default:
        throw new Error('Wallet type not supported');
    }
    return signature;
  }

  private async signWithMetamask(canonicalRequest, walletAddress) {
    // @ts-ignore
    if (!window.ethereum) {
      throw new Error('Metamask not installed');
    }

    // get chainId
    const chainId = web3.utils.toHex(parseInt(this.verificationMethod.blockchainAccountId.split(':')[1]));
    // @ts-ignore
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: chainId }],
    });

    // @ts-ignore

    // const accounts = await window.ethereum
    //   .request({
    //     method: 'wallet_requestPermissions',
    //     params: [
    //       {
    //         eth_accounts: {
    //           requiredMethods: ['personal_sign'],
    //         },
    //       },
    //     ],
    //   })
    //   .then((permissions) => {
    //     const accountsPermission = permissions.find((permission) => permission.parentCapability === 'eth_accounts');
    //     if (accountsPermission) {
    //       console.log('eth_accounts permission successfully requested!');
    //     }
    //   })
    //   .catch((error) => {
    //     if (error.code === 4001) {
    //       // EIP-1193 userRejectedRequest error
    //       console.log('Permissions needed to continue.');
    //     } else {
    //       console.error(error);
    //     }
    //   });

    // @ts-ignore
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    if (accounts[0].toLowerCase() !== walletAddress.toLowerCase()) {
      throw new Error('Metamask account does not match wallet address');
    }
    // @ts-ignore
    const signature = await window.ethereum.request({
      method: 'personal_sign',
      params: [canonicalRequest, accounts[0]],
    });
    return signature;
  }

  private async encryptDocument({ document }) {
    if (typeof document !== 'object') {
      throw new Error('Document is not an object');
    }
    // check if verification method type is for metamask or keplr

    // @ts-ignore
    if (!window.ethereum) {
      throw new Error('Metamask not installed');
    }

    // @ts-ignore
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });

    // @ts-ignore
    const encryptionPublicKey = await window.ethereum.request({
      method: 'eth_getEncryptionPublicKey',
      params: [accounts[0]], // you must have access to the specified account
    });

    const cannonizeString = JSON.stringify(document, function (key, value) {
      if (value && typeof value === 'object') {
        const newValue = Array.isArray(value) ? [] : {};
        Object.keys(value)
          .sort()
          .forEach(function (k) {
            newValue[k] = value[k];
          });
        return newValue;
      }
      return value;
    });
    const encryptedMessage = sigUtil.encrypt({
      publicKey: encryptionPublicKey,
      data: cannonizeString,
      version: 'x25519-xsalsa20-poly1305',
    });

    return encryptedMessage;
  }

  /**
   * Inserts a new docs in the data vault
   * @param document doc to be updated in plain text
   * @param documentId Id of the document
   * @param edvId Id of the data vault
   * @param sequence Optional sequence number, default is 0
   * @returns updated document
   */
  public async insertDoc({ document, documentId, sequence, edvId }) {
    // encrypt the document
    const encryptedDocument = await this.encryptDocument({ document });

    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';

    const headers = {
      created: Number(new Date()).toString(),
      'content-type': 'application/json',
      controller: this.verificationMethod.controller,
      vermethodid: this.verificationMethod.id,
      keyid: this.verificationMethod.id,
      vermethoddid: this.verificationMethod.id,
      algorithm: 'sha256-eth-personalSign',
    };

    const hsEncDoc = new HypersignEncryptedDocument({ data: encryptedDocument, id: documentId, sequence });

    const body = hsEncDoc.get();

    const { signature, canonicalHeaders, signedHeaders, payloadHash } = await this.signRequest({
      url: edvDocAddUrl,
      method: 'POST',
      query: null,
      keyId: this.verificationMethod.id,
      headers,
      body,
    });
    const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');

    headers[
      'Authorization'
    ] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;

    //cosmos-ADR036

    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'POST',
      body,
      headers,
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
  }: {
    document: any;
    documentId?: string;
    sequence?: number;
    edvId: string;
  }) {
    const encryptedDocument = await this.encryptDocument({ document });

    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/document';

    const headers = {
      created: Number(new Date()).toString(),
      'content-type': 'application/json',
      controller: this.verificationMethod.controller,
      vermethodid: this.verificationMethod.id,
      keyid: this.verificationMethod.id,
      vermethoddid: this.verificationMethod.id,
      algorithm: 'sha256-eth-personalSign',
    };

    const hsEncDoc = new HypersignEncryptedDocument({ data: encryptedDocument, id: documentId, sequence });

    const body = hsEncDoc.get();
    const method = 'PUT';
    const { signature, canonicalHeaders, signedHeaders, payloadHash } = await this.signRequest({
      url: edvDocAddUrl,
      method: 'PUT',
      query: null,
      keyId: this.verificationMethod.id,
      headers,
      body,
    });

    const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');

    headers[
      'Authorization'
    ] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;

    // make the call to store
    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'PUT',
      body,
      headers,
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

    // some auth should be here may  be capability check or something
    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'GET',
    });

    return resp;
  }

  public async decryptDocument({ encryptedDocument }) {
    // @ts-ignore
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const encryptedMessage = ethUtil.bufferToHex(Buffer.from(JSON.stringify(encryptedDocument)));

    // @ts-ignore
    const decryptedMessage = await window.ethereum.request({
      method: 'eth_decrypt',
      params: [encryptedMessage, accounts[0]],
    });
    return JSON.parse(decryptedMessage);
  }
}
