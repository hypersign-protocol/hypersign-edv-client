"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Pratap Mridha (Github @pratap2018)
 */
const multibase_1 = __importDefault(require("multibase"));
const config_1 = __importDefault(require("./config"));
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const tweetnacl_util_1 = __importDefault(require("tweetnacl-util"));
const utils_1 = __importDefault(require("./utils"));
const hsEncryptedDocument_1 = __importDefault(require("./hsEncryptedDocument"));
const hsEdvDataModels_1 = require("./hsEdvDataModels");
const web3_1 = __importDefault(require("web3"));
const ethUtil = require('ethereumjs-util');
const sigUtil = require('@metamask/eth-sig-util');
// Path: src/hsEdvClient.ts
const crypto_1 = __importDefault(require("crypto"));
const hsEdvDataModels_2 = require("./hsEdvDataModels");
// edv client using metamask
const multibaseBase58ToBase64 = (publicKeyMultibase) => {
    if (publicKeyMultibase == undefined) {
        return '';
    }
    const base64 = Buffer.from(multibase_1.default.decode(publicKeyMultibase)).toString('base64');
    return base64;
};
class HypersignEdvClientEcdsaSecp256k1 {
    constructor({ url, verificationMethod, keyAgreement, }) {
        this.edvsUrl = utils_1.default._sanitizeURL(url || config_1.default.Defaults.edvsBaseURl);
        if (verificationMethod.type !== 'EcdsaSecp256k1VerificationKey2019' &&
            verificationMethod.type !== 'EcdsaSecp256k1RecoveryMethod2020') {
            throw new Error('Verification method not supported');
        }
        this.verificationMethod = verificationMethod;
        if (keyAgreement) {
            this.keyAgreement = keyAgreement;
            this.encryptionPublicKeyBase64 = multibaseBase58ToBase64(this.keyAgreement.publicKeyMultibase);
        }
        else {
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
    registerEdv(config) {
        return __awaiter(this, void 0, void 0, function* () {
            this.verificationMethod = this.verificationMethod;
            const edvConfig = {};
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
                edvConfig.invokerVerificationMethodType = hsEdvDataModels_1.VerificationKeyTypes.EcdsaSecp256k1RecoveryMethod2020;
            }
            else if (this.verificationMethod.blockchainAccountId.includes('cosmos:')) {
                edvConfig.invokerVerificationMethodType = hsEdvDataModels_1.VerificationKeyTypes.EcdsaSecp256k1VerificationKey2019;
            }
            else {
                throw new Error('Verification method not supported');
            }
            const edvRegisterURl = this.edvsUrl + config_1.default.APIs.edvAPI;
            const headers = {
                created: Number(new Date()).toString(),
                'content-type': 'application/json',
                controller: this.verificationMethod.controller,
                vermethodid: this.verificationMethod.id,
                keyid: this.verificationMethod.id,
                vermethoddid: this.verificationMethod.id,
                algorithm: 'sha256-eth-personalSign',
            };
            const { signature, canonicalHeaders, signedHeaders, payloadHash } = yield this.signRequest({
                url: edvRegisterURl,
                method: 'POST',
                query: null,
                keyId: this.verificationMethod.id,
                headers,
                body: edvConfig,
            });
            const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
            headers['Authorization'] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;
            const resp = yield utils_1.default._makeAPICall({
                url: edvRegisterURl,
                method: 'POST',
                body: edvConfig,
                headers,
            });
            // attaching the newly created edv id
            edvConfig.id = resp.id;
            return edvConfig;
        });
    }
    canonicalizeJSON(json) {
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
                    }
                    else {
                        return val;
                    }
                });
            }
            else if (typeof value === 'object' && value !== null) {
                return Object.keys(value)
                    .sort()
                    .reduce((acc, curr) => {
                    acc[curr] = value[curr];
                    return acc;
                }, {});
            }
            else {
                return value;
            }
        });
        // Step 5: Convert back to string
        const sortedString = JSON.stringify(sortedJson);
        return sortedString;
    }
    createCanonicalRequest({ url, method, query, headers, body }) {
        return __awaiter(this, void 0, void 0, function* () {
            let action = 'read';
            if (method.toUpperCase() === 'POST' || method.toUpperCase() === 'PUT' || method.toUpperCase() === 'DELETE') {
                action = 'write';
            }
            let payloadHash;
            if (typeof body == 'object') {
                body = this.canonicalizeJSON(body);
                if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
                    payloadHash = yield window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(body || '')).then((hash) => {
                        const hashArray = Array.from(new Uint8Array(hash));
                        const base64 = btoa(String.fromCharCode(...hashArray));
                        return base64;
                    });
                }
                else {
                    payloadHash = crypto_1.default
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
            const canonicalRequest = [method.toUpperCase(), canonicalURI, canonicalQueryString, canonicalHeaders, '', signedHeaders].join('\n');
            return { canonicalRequest, canonicalHeaders, signedHeaders, payloadHash };
        });
    }
    signRequest({ url, method, query, headers, body, keyId }) {
        return __awaiter(this, void 0, void 0, function* () {
            const { canonicalRequest, canonicalHeaders, signedHeaders, payloadHash } = yield this.createCanonicalRequest({
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
                walletType = hsEdvDataModels_2.WalletTypes.Metamask;
            }
            else {
                walletType = hsEdvDataModels_2.WalletTypes.Keplr;
            }
            const signature = yield this.sign(canonicalRequest, walletAddress, walletType);
            return { signature, canonicalHeaders, signedHeaders, payloadHash };
        });
    }
    sign(canonicalRequest, walletAddress, walletType) {
        return __awaiter(this, void 0, void 0, function* () {
            let signature;
            switch (walletType) {
                case hsEdvDataModels_2.WalletTypes.Metamask:
                    signature = yield this.signWithMetamask(canonicalRequest, walletAddress);
                    break;
                case hsEdvDataModels_2.WalletTypes.Keplr:
                    throw new Error('Wallet type not supported');
                    //signature = await this.signWithKeplr(canonicalRequest,walletAddress)
                    break;
                default:
                    throw new Error('Wallet type not supported');
            }
            return signature;
        });
    }
    signWithMetamask(canonicalRequest, walletAddress) {
        return __awaiter(this, void 0, void 0, function* () {
            // @ts-ignore
            if (!window.ethereum) {
                throw new Error('Metamask not installed');
            }
            // get chainId
            const chainId = web3_1.default.utils.toHex(parseInt(this.verificationMethod.blockchainAccountId.split(':')[1]));
            // @ts-ignore
            yield window.ethereum.request({
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
            const accounts = yield window.ethereum.request({ method: 'eth_requestAccounts' });
            if (accounts[0].toLowerCase() !== walletAddress.toLowerCase()) {
                throw new Error('Metamask account does not match wallet address');
            }
            // @ts-ignore
            const signature = yield window.ethereum.request({
                method: 'personal_sign',
                params: [canonicalRequest, accounts[0]],
            });
            return signature;
        });
    }
    encryptDocument({ document, recipients }) {
        return __awaiter(this, void 0, void 0, function* () {
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
            const accounts = yield window.ethereum.request({ method: 'eth_requestAccounts' });
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
        });
    }
    generateRandomString(length) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,!?;:\'"()[]{}-+_=*/\\|@#$%&<>';
        let result = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * characters.length);
            result += characters.charAt(randomIndex);
        }
        return result;
    }
    encrypt(msgParams, recipients) {
        const msgParamsUInt8Array = tweetnacl_util_1.default.decodeUTF8(msgParams);
        // const symmetricKey = nacl.randomBytes(nacl.secretbox.keyLength);
        const symmetricKey = tweetnacl_util_1.default.decodeUTF8(this.generateRandomString(32));
        const encryptedSymmetricKeys = Array();
        const ephemeralKeyPair = tweetnacl_1.default.box.keyPair();
        const recipientNonce = tweetnacl_1.default.randomBytes(tweetnacl_1.default.box.nonceLength);
        recipients.forEach((recipient) => {
            // Generate a random nonce for each recipient
            // Encrypt the symmetric key with each recipient's public key
            const publicKeyBase64 = tweetnacl_util_1.default.decodeBase64(recipient.encryptionPublicKeyBase64);
            const encryptedSymmetricKey = tweetnacl_1.default.box(symmetricKey, recipientNonce, publicKeyBase64, ephemeralKeyPair.secretKey);
            encryptedSymmetricKeys.push({ encryptedSymmetricKey: tweetnacl_util_1.default.encodeBase64(encryptedSymmetricKey), keyId: recipient.id });
            // Encrypt the message using the symmetric key
        });
        const encryptedMessage = tweetnacl_1.default.secretbox(msgParamsUInt8Array, recipientNonce, symmetricKey);
        const output = {
            version: 'x25519-xsalsa20-poly1305',
            nonce: tweetnacl_util_1.default.encodeBase64(recipientNonce),
            ephemPublicKey: tweetnacl_util_1.default.encodeBase64(ephemeralKeyPair.publicKey),
            recipients: encryptedSymmetricKeys.map((encryptedKey) => {
                return {
                    encrypted_Key: encryptedKey.encryptedSymmetricKey,
                    keyId: encryptedKey.keyId,
                };
            }),
            ciphertext: tweetnacl_util_1.default.encodeBase64(encryptedMessage),
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
    insertDoc({ document, documentId, sequence, edvId, metadata, recipients }) {
        var _a, _b, _c, _d, _e;
        return __awaiter(this, void 0, void 0, function* () {
            if (recipients) {
                if (!Array.isArray(recipients)) {
                    throw new Error('recipients must be an array');
                }
                if (recipients.length == 0) {
                    recipients = [];
                    recipients.push({
                        id: (_a = this.keyAgreement) === null || _a === void 0 ? void 0 : _a.id,
                        type: (_b = this.keyAgreement) === null || _b === void 0 ? void 0 : _b.type,
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
            }
            else {
                recipients = [];
                recipients.push({
                    id: (_c = this.keyAgreement) === null || _c === void 0 ? void 0 : _c.id,
                    type: (_d = this.keyAgreement) === null || _d === void 0 ? void 0 : _d.type,
                    encryptionPublicKeyBase64: multibaseBase58ToBase64((_e = this.keyAgreement) === null || _e === void 0 ? void 0 : _e.id.split('#')[1]),
                });
            }
            // encrypt the document
            const encryptedDocument = yield this.encryptDocument({ document, recipients });
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
            const headers = {
                created: Number(new Date()).toString(),
                'content-type': 'application/json',
                controller: this.verificationMethod.controller,
                vermethodid: this.verificationMethod.id,
                keyid: this.verificationMethod.id,
                vermethoddid: this.verificationMethod.id,
                algorithm: 'sha256-eth-personalSign',
            };
            const hsEncDoc = new hsEncryptedDocument_1.default({ encryptedData: encryptedDocument, id: documentId, metadata, sequence });
            const body = hsEncDoc.get();
            const { signature, canonicalHeaders, signedHeaders, payloadHash } = yield this.signRequest({
                url: edvDocAddUrl,
                method: 'POST',
                query: null,
                keyId: this.verificationMethod.id,
                headers,
                body,
            });
            const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
            headers['Authorization'] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;
            //cosmos-ADR036
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'POST',
                body,
                headers,
            });
            return resp;
        });
    }
    /**
     * Updates doc in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns newly created document
     */
    updateDoc({ document, documentId, sequence, edvId, metadata, }) {
        return __awaiter(this, void 0, void 0, function* () {
            const encryptedDocument = yield this.encryptDocument({ document });
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
            const headers = {
                created: Number(new Date()).toString(),
                'content-type': 'application/json',
                controller: this.verificationMethod.controller,
                vermethodid: this.verificationMethod.id,
                keyid: this.verificationMethod.id,
                vermethoddid: this.verificationMethod.id,
                algorithm: 'sha256-eth-personalSign',
            };
            const hsEncDoc = new hsEncryptedDocument_1.default({ encryptedData: encryptedDocument, metadata, id: documentId, sequence });
            const body = hsEncDoc.get();
            const method = 'PUT';
            const { signature, canonicalHeaders, signedHeaders, payloadHash } = yield this.signRequest({
                url: edvDocAddUrl,
                method: 'PUT',
                query: null,
                keyId: this.verificationMethod.id,
                headers,
                body,
            });
            const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
            headers['Authorization'] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;
            // make the call to store
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'PUT',
                body,
                headers,
            });
            return resp;
        });
    }
    /**
     * Fetchs docs related to a particular documentId
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns all documents (with sequences if not passed) for a documentId
     */
    fetchDoc({ documentId, edvId, sequence }) {
        return __awaiter(this, void 0, void 0, function* () {
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document/' + documentId;
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
            const { signature, canonicalHeaders, signedHeaders, payloadHash } = yield this.signRequest({
                url: edvDocAddUrl,
                method: 'GET',
                query: null,
                keyId: this.verificationMethod.id,
                headers,
                body: undefined,
            });
            const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
            headers['Authorization'] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'GET',
                headers,
                body: undefined,
            });
            return resp;
        });
    }
    decryptDocument({ encryptedDocument, recipient, }) {
        return __awaiter(this, void 0, void 0, function* () {
            // @ts-ignore
            // const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            // const encryptedMessage = ethUtil.bufferToHex(Buffer.from(JSON.stringify(encryptedDocument)));
            // @ts-ignore
            // const decryptedMessage = await window.ethereum.request({
            //   method: 'eth_decrypt',
            //   params: [encryptedMessage, accounts[0]],
            // })
            const decryptedMessage = yield this.decrypt(encryptedDocument, recipient.id);
            return JSON.parse(decryptedMessage);
        });
    }
    // private naclDecodeHex(msgHex) {
    //   const msgBase64 = Buffer.from(msgHex, 'hex').toString('base64');
    //   return naclUtil.decodeBase64(msgBase64);
    // }
    decrypt(encryptedMessage, keyId) {
        return __awaiter(this, void 0, void 0, function* () {
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
            const accounts = yield window.ethereum.request({ method: 'eth_requestAccounts' });
            //@ts-ignore
            const decryptedMessage = yield window.ethereum.request({
                method: 'eth_decrypt',
                params: [buffredEncryptedMessage, accounts[0]],
            });
            const symmetricKey = tweetnacl_util_1.default.decodeUTF8(decryptedMessage);
            const finalMessage = tweetnacl_1.default.secretbox.open(tweetnacl_util_1.default.decodeBase64(encryptedMessage.ciphertext), tweetnacl_util_1.default.decodeBase64(encryptedMessage.nonce), symmetricKey);
            //   console.log(finalMessage);
            if (finalMessage == null) {
                throw Error('Decryption failed');
            }
            else {
                return tweetnacl_util_1.default.encodeUTF8(finalMessage);
            }
            //   const output = naclUtil.encodeUTF8(decryptedMessage);
        });
    }
    fetchAllDocs({ edvId, limit, page }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!limit)
                limit = 10;
            if (!page)
                page = 1;
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/documents' + `?limit=${limit}&page=${page}`;
            const headers = {
                created: Number(new Date()).toString(),
                'content-type': 'application/json',
                controller: this.verificationMethod.controller,
                vermethodid: this.verificationMethod.id,
                keyid: this.verificationMethod.id,
                vermethoddid: this.verificationMethod.id,
                algorithm: 'sha256-eth-personalSign',
            };
            const { signature, canonicalHeaders, signedHeaders, payloadHash } = yield this.signRequest({
                url: edvDocAddUrl,
                method: 'GET',
                query: null,
                keyId: this.verificationMethod.id,
                headers,
                body: undefined,
            });
            const base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
            headers['Authorization'] = `Signature keyId="${this.verificationMethod.id}",algorithm="sha256-eth-personalSign",headers="${signedHeaders}",signature="${base64}"`;
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'GET',
                headers,
                body: undefined,
            });
            return resp;
        });
    }
}
exports.default = HypersignEdvClientEcdsaSecp256k1;
