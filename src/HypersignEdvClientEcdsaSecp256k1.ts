/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Pratap Mridha (Github @pratap2018)
 */
import multibase from 'multibase';
import Config from './config';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
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

interface KeyAgreementKeyPair {
  id: string;
  controller?: string;
  type: 'X25519KeyAgreementKeyEIP5630';
  publicKeyMultibase: string;
}

// edv client using metamask

const multibaseBase58ToBase64 = (publicKeyMultibase: string | undefined) => {
  if (publicKeyMultibase == undefined) {
    return '';
  }
  const base64 = Buffer.from(multibase.decode(publicKeyMultibase)).toString('base64');
  return base64;
};

export default class HypersignEdvClientEcdsaSecp256k1 {
  private edvsUrl: string;
  private verificationMethod: IVerifcationMethod;
  private keyAgreement?: KeyAgreementKeyPair;
  private encryptionPublicKeyBase64?: string;

  constructor({
    url,
    verificationMethod,
    keyAgreement,
  }: {
    url?: string;
    verificationMethod: IVerifcationMethod;
    keyAgreement?: KeyAgreementKeyPair;
  }) {
    this.edvsUrl = Utils._sanitizeURL(url || Config.Defaults.edvsBaseURl);
    if (
      verificationMethod.type !== 'EcdsaSecp256k1VerificationKey2019' &&
      verificationMethod.type !== 'EcdsaSecp256k1RecoveryMethod2020'
    ) {
      throw new Error('Verification method not supported');
    }
    this.verificationMethod = verificationMethod;
    if (keyAgreement) {
      this.keyAgreement = keyAgreement;
      this.encryptionPublicKeyBase64 = multibaseBase58ToBase64(this.keyAgreement.publicKeyMultibase);
    } else {
      this.keyAgreement = undefined;
      this.encryptionPublicKeyBase64 = undefined;
    }
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

    const headers = {
      created: Number(new Date()).toString(),
      'content-type': 'application/json',
      controller: this.verificationMethod.controller,
      vermethodid: this.verificationMethod.id,
      keyid: this.verificationMethod.id,
      vermethoddid: this.verificationMethod.id,
      algorithm: 'sha256-eth-personalSign',
    };

    const { signature, canonicalHeaders, signedHeaders, payloadHash } = await this.signRequest({
      url: edvRegisterURl,
      method: 'POST',
      query: null,
      keyId: this.verificationMethod.id,
      headers,
      body: edvConfig,
    });
    const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
    headers[
      'Authorization'
    ] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;

    const resp: IDataVaultConfiguration = await Utils._makeAPICall({
      url: edvRegisterURl,
      method: 'POST',
      body: edvConfig,
      headers,
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
    let payloadHash;

    if (typeof body == 'object') {
      body = this.canonicalizeJSON(body);
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
      if (method.toUpperCase() !== 'GET') {
        headers['digest'] = `SHA-256=${payloadHash}`;
      }
    }

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

  private async encryptDocument({ document, recipients }: { document: object; recipients?: any }) {
    if (typeof document !== 'object') {
      throw new Error('Document is not an object');
    }
    // check if verification method type is for metamask or keplr

    // @ts-ignore
    if (!window.ethereum) {
      throw new Error('Metamask not installed');
    }
    let encryptionPublicKey;
    // @ts-ignore
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });

    // if (!recipients) {
    //   // @ts-ignore
    //   encryptionPublicKey = await window.ethereum.request({
    //     method: 'eth_getEncryptionPublicKey',
    //     params: [accounts[0]], // you must have access to the specified account
    //   });
    // } else {
    //   encryptionPublicKey = this.encryptionPublicKeyBase64;
    // }

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

    // const encryptedMessage = sigUtil.encrypt({
    //   publicKey: encryptionPublicKey,
    //   data: cannonizeString,
    //   version: 'x25519-xsalsa20-poly1305',
    // });

    const encryptedMessage = this.encrypt(cannonizeString, recipients);

    return encryptedMessage;
  }
  private generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,!?;:\'"()[]{}-+_=*/\\|@#$%&<>';

    let result = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      result += characters.charAt(randomIndex);
    }

    return result;
  }
  private encrypt(
    msgParams,
    recipients: Array<{
      id: string;
      type: string;
      encryptionPublicKeyBase64: string;
    }>,
  ) {
    const msgParamsUInt8Array = naclUtil.decodeUTF8(msgParams);

    // const symmetricKey = nacl.randomBytes(nacl.secretbox.keyLength);
    const symmetricKey = naclUtil.decodeUTF8(this.generateRandomString(32));

    const encryptedSymmetricKeys = Array<{ encryptedSymmetricKey: string; keyId: any }>();
    const ephemeralKeyPair = nacl.box.keyPair();
    const recipientNonce = nacl.randomBytes(nacl.box.nonceLength);

    recipients.forEach((recipient) => {
      // Generate a random nonce for each recipient
      // Encrypt the symmetric key with each recipient's public key
      const publicKeyBase64 = naclUtil.decodeBase64(recipient.encryptionPublicKeyBase64);
      const encryptedSymmetricKey = nacl.box(symmetricKey, recipientNonce, publicKeyBase64, ephemeralKeyPair.secretKey);
      encryptedSymmetricKeys.push({ encryptedSymmetricKey: naclUtil.encodeBase64(encryptedSymmetricKey), keyId: recipient.id });

      // Encrypt the message using the symmetric key
    });

    const encryptedMessage = nacl.secretbox(msgParamsUInt8Array, recipientNonce, symmetricKey);

    const output = {
      version: 'x25519-xsalsa20-poly1305',
      nonce: naclUtil.encodeBase64(recipientNonce),
      ephemPublicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
      recipients: encryptedSymmetricKeys.map((encryptedKey) => {
        return {
          encrypted_Key: encryptedKey.encryptedSymmetricKey,
          keyId: encryptedKey.keyId,
        };
      }),
      ciphertext: naclUtil.encodeBase64(encryptedMessage),
    };

    return output;
  }
  /**
   * Inserts a new docs in the data vault
   * @param document doc to be updated in plain text
   * @param documentId Id of the document
   * @param edvId Id of the data vault
   * @param sequence Optional sequence number, default is 0
   * @returns updated document
   */
  public async insertDoc({ document, documentId, sequence, edvId, metadata, recipients }) {
    if (recipients) {
      if (!Array.isArray(recipients)) {
        throw new Error('recipients must be an array');
      }

      if (recipients.length == 0) {
        recipients = [];
        recipients.push({
          id: this.keyAgreement?.id,
          type: this.keyAgreement?.type,
        });
      }

      recipients.forEach((recipient) => {
        if (!recipient.id) {
          throw new Error('recipient must have id');
        }
        if (recipient.type !== 'X25519KeyAgreementKeyEIP5630') {
          throw new Error('recipient must have type of X25519KeyAgreementKeyEIP5630');
        }

        recipient.encryptionPublicKeyBase64 = multibaseBase58ToBase64(recipient.id.split('#')[1]);
      });
    } else {
      recipients = [];
      recipients.push({
        id: this.keyAgreement?.id,
        type: this.keyAgreement?.type,
        encryptionPublicKeyBase64: multibaseBase58ToBase64(this.keyAgreement?.id.split('#')[1]),
      });
    }

    // encrypt the document
    const encryptedDocument = await this.encryptDocument({ document, recipients });

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

    const hsEncDoc = new HypersignEncryptedDocument({ encryptedData: encryptedDocument, id: documentId, metadata, sequence });

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
    metadata,
  }: {
    document: any;
    documentId?: string;
    sequence?: number;
    edvId: string;
    metadata?: any;
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

    const hsEncDoc = new HypersignEncryptedDocument({ encryptedData: encryptedDocument, metadata, id: documentId, sequence });

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

    const headers = {
      created: Number(new Date()).toString(),
      'content-type': 'application/json',
      controller: this.verificationMethod.controller,
      vermethodid: this.verificationMethod.id,
      keyid: this.verificationMethod.id,
      vermethoddid: this.verificationMethod.id,
      algorithm: 'sha256-eth-personalSign',
    };

    const { signature, canonicalHeaders, signedHeaders, payloadHash } = await this.signRequest({
      url: edvDocAddUrl,
      method: 'GET',
      query: null,
      keyId: this.verificationMethod.id,
      headers,
      body: undefined,
    });

    const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
    headers[
      'Authorization'
    ] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;

    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'GET',
      headers,
      body: undefined,
    });

    return resp;
  }

  public async decryptDocument({
    encryptedDocument,
    recipient,
  }: {
    encryptedDocument: any;
    recipient: {
      id: string;
      type?: string;
    };
  }) {
    // @ts-ignore
    // const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    // const encryptedMessage = ethUtil.bufferToHex(Buffer.from(JSON.stringify(encryptedDocument)));

    // @ts-ignore
    // const decryptedMessage = await window.ethereum.request({
    //   method: 'eth_decrypt',
    //   params: [encryptedMessage, accounts[0]],

    // })
    const decryptedMessage = await this.decrypt(encryptedDocument, recipient.id);
    return JSON.parse(decryptedMessage);
  }

  // private naclDecodeHex(msgHex) {
  //   const msgBase64 = Buffer.from(msgHex, 'hex').toString('base64');
  //   return naclUtil.decodeBase64(msgBase64);
  // }
  private async decrypt(encryptedMessage, keyId) {
    const encrypted_Key = encryptedMessage.recipients.find((recipient) => recipient.keyId === keyId).encrypted_Key;
    const symmetricKey_Encrypted = {
      version: encryptedMessage.version,
      nonce: encryptedMessage.nonce,
      ephemPublicKey: encryptedMessage.ephemPublicKey,
      ciphertext: encrypted_Key,
    };

    // const nonce = naclUtil.decodeBase64(symmetricKey_Encrypted.nonce);
    // const ciphertext = naclUtil.decodeBase64(symmetricKey_Encrypted.ciphertext);
    // const ephemPublicKey = naclUtil.decodeBase64(symmetricKey_Encrypted.ephemPublicKey);

    // trick to get the symmetric key

    const encryptedMessageKey = {
      version: encryptedMessage.version,
      ciphertext: symmetricKey_Encrypted.ciphertext,
      nonce: symmetricKey_Encrypted.nonce,
      ephemPublicKey: symmetricKey_Encrypted.ephemPublicKey,
    };

    const buffredEncryptedMessage = ethUtil.bufferToHex(Buffer.from(JSON.stringify(encryptedMessageKey)));

    // @ts-ignore
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    //@ts-ignore
    const decryptedMessage = await window.ethereum.request({
      method: 'eth_decrypt',
      params: [buffredEncryptedMessage, accounts[0]],
    });

    const symmetricKey = naclUtil.decodeUTF8(decryptedMessage);

    const finalMessage = nacl.secretbox.open(
      naclUtil.decodeBase64(encryptedMessage.ciphertext),
      naclUtil.decodeBase64(encryptedMessage.nonce),
      symmetricKey,
    );
    //   console.log(finalMessage);
    if (finalMessage == null) {
      throw Error('Decryption failed');
    } else {
      return naclUtil.encodeUTF8(finalMessage);
    }
    //   const output = naclUtil.encodeUTF8(decryptedMessage);
  }

  public async fetchAllDocs({ edvId, limit, page }) {
    if (!limit) limit = 10;
    if (!page) page = 1;
    const edvDocAddUrl = this.edvsUrl + Config.APIs.edvAPI + '/' + edvId + '/documents' + `?limit=${limit}&page=${page}`;

    const headers = {
      created: Number(new Date()).toString(),
      'content-type': 'application/json',
      controller: this.verificationMethod.controller,
      vermethodid: this.verificationMethod.id,
      keyid: this.verificationMethod.id,
      vermethoddid: this.verificationMethod.id,
      algorithm: 'sha256-eth-personalSign',
    };

    const { signature, canonicalHeaders, signedHeaders, payloadHash } = await this.signRequest({
      url: edvDocAddUrl,
      method: 'GET',
      query: null,
      keyId: this.verificationMethod.id,
      headers,
      body: undefined,
    });

    const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
    headers[
      'Authorization'
    ] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;

    const resp = await Utils._makeAPICall({
      url: edvDocAddUrl,
      method: 'GET',
      headers,
      body: undefined,
    });

    return resp;
  }
}
