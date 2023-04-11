"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Pratap Mridha (Github @pratap2018)
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var config_1 = __importDefault(require("./config"));
var utils_1 = __importDefault(require("./utils"));
var hsEncryptedDocument_1 = __importDefault(require("./hsEncryptedDocument"));
var hsEdvDataModels_1 = require("./hsEdvDataModels");
var web3_1 = __importDefault(require("web3"));
var ethUtil = require('ethereumjs-util');
var sigUtil = require('@metamask/eth-sig-util');
// Path: src/hsEdvClient.ts
var crypto_1 = __importDefault(require("crypto"));
var hsEdvDataModels_2 = require("./hsEdvDataModels");
// edv client using metamask
var HypersignEdvClientEcdsaSecp256k1 = /** @class */ (function () {
    function HypersignEdvClientEcdsaSecp256k1(_a) {
        var url = _a.url, verificationMethod = _a.verificationMethod;
        this.edvsUrl = utils_1.default._sanitizeURL(url || config_1.default.Defaults.edvsBaseURl);
        if (verificationMethod.type !== 'EcdsaSecp256k1VerificationKey2019' &&
            verificationMethod.type !== 'EcdsaSecp256k1RecoveryMethod2020') {
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
    HypersignEdvClientEcdsaSecp256k1.prototype.registerEdv = function (config) {
        return __awaiter(this, void 0, void 0, function () {
            var edvConfig, edvRegisterURl, resp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        this.verificationMethod = this.verificationMethod;
                        edvConfig = {};
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
                        edvRegisterURl = this.edvsUrl + config_1.default.APIs.edvAPI;
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvRegisterURl,
                                method: 'POST',
                                body: edvConfig,
                            })];
                    case 1:
                        resp = _a.sent();
                        // attaching the newly created edv id
                        edvConfig.id = resp.id;
                        return [2 /*return*/, edvConfig];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.canonicalizeJSON = function (json) {
        // Step 1: Convert to JSON string
        var jsonString = JSON.stringify(json);
        // Step 2: Normalize line endings to CRLF
        var crlfString = jsonString.replace(/\r?\n/g, '\r\n');
        // Step 3: Remove all whitespace between tokens
        var compactString = crlfString.replace(/\s+/g, '');
        // Step 4: Sort the keys in every object in the JSON structure
        var sortedJson = JSON.parse(crlfString, function (key, value) {
            if (Array.isArray(value)) {
                return value.map(function (val) {
                    if (typeof val === 'object' && val !== null) {
                        return Object.keys(val)
                            .sort()
                            .reduce(function (acc, curr) {
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
                    .reduce(function (acc, curr) {
                    acc[curr] = value[curr];
                    return acc;
                }, {});
            }
            else {
                return value;
            }
        });
        // Step 5: Convert back to string
        var sortedString = JSON.stringify(sortedJson);
        return sortedString;
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.createCanonicalRequest = function (_a) {
        var url = _a.url, method = _a.method, query = _a.query, headers = _a.headers, body = _a.body;
        return __awaiter(this, void 0, void 0, function () {
            var action, payloadHash, urlObj, path, canonicalURI, canonicalQueryString, entries, result_1, _i, entries_1, _b, key, value, canonicalHeaders, signedHeaders, canonicalRequest;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        action = 'read';
                        if (method.toUpperCase() === 'POST' || method.toUpperCase() === 'PUT' || method.toUpperCase() === 'DELETE') {
                            action = 'write';
                        }
                        if (typeof body == 'object') {
                            body = this.canonicalizeJSON(body);
                        }
                        if (!(typeof window !== 'undefined' && window.crypto && window.crypto.subtle)) return [3 /*break*/, 2];
                        return [4 /*yield*/, window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(body || '')).then(function (hash) {
                                var hashArray = Array.from(new Uint8Array(hash));
                                var base64 = btoa(String.fromCharCode.apply(String, hashArray));
                                return base64;
                            })];
                    case 1:
                        payloadHash = _c.sent();
                        return [3 /*break*/, 3];
                    case 2:
                        payloadHash = crypto_1.default
                            .createHash('sha256')
                            .update(body || '')
                            .digest('base64');
                        payloadHash = payloadHash.toString('base64');
                        _c.label = 3;
                    case 3:
                        headers['digest'] = "SHA-256=".concat(payloadHash);
                        urlObj = new URL(url);
                        headers['host'] = urlObj.host;
                        query = urlObj.searchParams;
                        path = urlObj.pathname;
                        headers['request-target'] = urlObj.href;
                        headers['capability-invocation'] = "zcap id=\"urn:zcap:root:".concat(encodeURI(headers['request-target']), "\",action=\"").concat(action, "\"");
                        canonicalURI = encodeURIComponent(path);
                        canonicalQueryString = '';
                        if (query) {
                            entries = query.entries();
                            result_1 = {};
                            for (_i = 0, entries_1 = entries; _i < entries_1.length; _i++) {
                                _b = entries_1[_i], key = _b[0], value = _b[1];
                                // each 'entry' is a [key, value] tupple
                                result_1[key] = value;
                            }
                            canonicalQueryString = Object.keys(result_1)
                                .sort()
                                .map(function (key) { return "".concat(encodeURIComponent(key), "=").concat(encodeURIComponent(result_1[key])); })
                                .join('&');
                        }
                        canonicalHeaders = Object.keys(headers)
                            .map(function (key) { return "".concat(key.toLowerCase(), ":").concat(headers[key].trim().replace(/\s+/g, ' ')); })
                            .sort()
                            .join('\n');
                        signedHeaders = Object.keys(headers)
                            .map(function (key) {
                            var k = key.toLowerCase();
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
                        canonicalRequest = [method.toUpperCase(), canonicalURI, canonicalQueryString, canonicalHeaders, '', signedHeaders].join('\n');
                        return [2 /*return*/, { canonicalRequest: canonicalRequest, canonicalHeaders: canonicalHeaders, signedHeaders: signedHeaders, payloadHash: payloadHash }];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.signRequest = function (_a) {
        var url = _a.url, method = _a.method, query = _a.query, headers = _a.headers, body = _a.body, keyId = _a.keyId;
        return __awaiter(this, void 0, void 0, function () {
            var _b, canonicalRequest, canonicalHeaders, signedHeaders, payloadHash, publicKeyOrAddress, walletType, walletAddress, signature;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0: return [4 /*yield*/, this.createCanonicalRequest({
                            url: url,
                            method: method,
                            query: query,
                            headers: headers,
                            body: body,
                        })];
                    case 1:
                        _b = _c.sent(), canonicalRequest = _b.canonicalRequest, canonicalHeaders = _b.canonicalHeaders, signedHeaders = _b.signedHeaders, payloadHash = _b.payloadHash;
                        publicKeyOrAddress = keyId.split('#')[1];
                        walletAddress = publicKeyOrAddress.split(':')[2];
                        if (publicKeyOrAddress.includes('eip155:')) {
                            walletType = hsEdvDataModels_2.WalletTypes.Metamask;
                        }
                        else {
                            walletType = hsEdvDataModels_2.WalletTypes.Keplr;
                        }
                        return [4 /*yield*/, this.sign(canonicalRequest, walletAddress, walletType)];
                    case 2:
                        signature = _c.sent();
                        return [2 /*return*/, { signature: signature, canonicalHeaders: canonicalHeaders, signedHeaders: signedHeaders, payloadHash: payloadHash }];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.sign = function (canonicalRequest, walletAddress, walletType) {
        return __awaiter(this, void 0, void 0, function () {
            var signature, _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        _a = walletType;
                        switch (_a) {
                            case hsEdvDataModels_2.WalletTypes.Metamask: return [3 /*break*/, 1];
                            case hsEdvDataModels_2.WalletTypes.Keplr: return [3 /*break*/, 3];
                        }
                        return [3 /*break*/, 4];
                    case 1: return [4 /*yield*/, this.signWithMetamask(canonicalRequest, walletAddress)];
                    case 2:
                        signature = _b.sent();
                        return [3 /*break*/, 5];
                    case 3: throw new Error('Wallet type not supported');
                    case 4: throw new Error('Wallet type not supported');
                    case 5: return [2 /*return*/, signature];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.signWithMetamask = function (canonicalRequest, walletAddress) {
        return __awaiter(this, void 0, void 0, function () {
            var chainId, accounts, signature;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // @ts-ignore
                        if (!window.ethereum) {
                            throw new Error('Metamask not installed');
                        }
                        chainId = web3_1.default.utils.toHex(parseInt(this.verificationMethod.blockchainAccountId.split(':')[1]));
                        // @ts-ignore
                        return [4 /*yield*/, window.ethereum.request({
                                method: 'wallet_switchEthereumChain',
                                params: [{ chainId: chainId }],
                            })];
                    case 1:
                        // @ts-ignore
                        _a.sent();
                        return [4 /*yield*/, window.ethereum.request({ method: 'eth_requestAccounts' })];
                    case 2:
                        accounts = _a.sent();
                        if (accounts[0].toLowerCase() !== walletAddress.toLowerCase()) {
                            throw new Error('Metamask account does not match wallet address');
                        }
                        return [4 /*yield*/, window.ethereum.request({
                                method: 'personal_sign',
                                params: [canonicalRequest, accounts[0]],
                            })];
                    case 3:
                        signature = _a.sent();
                        return [2 /*return*/, signature];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.encryptDocument = function (_a) {
        var document = _a.document;
        return __awaiter(this, void 0, void 0, function () {
            var accounts, encryptionPublicKey, cannonizeString, encryptedMessage;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (typeof document !== 'object') {
                            throw new Error('Document is not an object');
                        }
                        // check if verification method type is for metamask or keplr
                        // @ts-ignore
                        if (!window.ethereum) {
                            throw new Error('Metamask not installed');
                        }
                        return [4 /*yield*/, window.ethereum.request({ method: 'eth_requestAccounts' })];
                    case 1:
                        accounts = _b.sent();
                        return [4 /*yield*/, window.ethereum.request({
                                method: 'eth_getEncryptionPublicKey',
                                params: [accounts[0]], // you must have access to the specified account
                            })];
                    case 2:
                        encryptionPublicKey = _b.sent();
                        cannonizeString = JSON.stringify(document, function (key, value) {
                            if (value && typeof value === 'object') {
                                var newValue_1 = Array.isArray(value) ? [] : {};
                                Object.keys(value)
                                    .sort()
                                    .forEach(function (k) {
                                    newValue_1[k] = value[k];
                                });
                                return newValue_1;
                            }
                            return value;
                        });
                        encryptedMessage = sigUtil.encrypt({
                            publicKey: encryptionPublicKey,
                            data: cannonizeString,
                            version: 'x25519-xsalsa20-poly1305',
                        });
                        return [2 /*return*/, encryptedMessage];
                }
            });
        });
    };
    /**
     * Inserts a new docs in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns updated document
     */
    HypersignEdvClientEcdsaSecp256k1.prototype.insertDoc = function (_a) {
        var document = _a.document, documentId = _a.documentId, sequence = _a.sequence, edvId = _a.edvId;
        return __awaiter(this, void 0, void 0, function () {
            var encryptedDocument, edvDocAddUrl, headers, hsEncDoc, body, _b, signature, canonicalHeaders, signedHeaders, payloadHash, base64, resp;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0: return [4 /*yield*/, this.encryptDocument({ document: document })];
                    case 1:
                        encryptedDocument = _c.sent();
                        edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
                        headers = {
                            created: Number(new Date()).toString(),
                            'content-type': 'application/json',
                            controller: this.verificationMethod.controller,
                            vermethodid: this.verificationMethod.id,
                            keyid: this.verificationMethod.id,
                            vermethoddid: this.verificationMethod.id,
                            algorithm: 'sha256-eth-personalSign',
                        };
                        hsEncDoc = new hsEncryptedDocument_1.default({ data: encryptedDocument, id: documentId, sequence: sequence });
                        body = hsEncDoc.get();
                        return [4 /*yield*/, this.signRequest({
                                url: edvDocAddUrl,
                                method: 'POST',
                                query: null,
                                keyId: this.verificationMethod.id,
                                headers: headers,
                                body: body,
                            })];
                    case 2:
                        _b = _c.sent(), signature = _b.signature, canonicalHeaders = _b.canonicalHeaders, signedHeaders = _b.signedHeaders, payloadHash = _b.payloadHash;
                        base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
                        headers['Authorization'] = "Signature keyId=\"".concat(this.verificationMethod.id, "\",algorithm=\"sha256-eth-personalSign\",headers=\"").concat(signedHeaders, "\",signature=\"").concat(base64, "\"");
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvDocAddUrl,
                                method: 'POST',
                                body: body,
                                headers: headers,
                            })];
                    case 3:
                        resp = _c.sent();
                        return [2 /*return*/, resp];
                }
            });
        });
    };
    /**
     * Updates doc in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns newly created document
     */
    HypersignEdvClientEcdsaSecp256k1.prototype.updateDoc = function (_a) {
        var document = _a.document, documentId = _a.documentId, sequence = _a.sequence, edvId = _a.edvId;
        return __awaiter(this, void 0, void 0, function () {
            var encryptedDocument, edvDocAddUrl, headers, hsEncDoc, body, method, _b, signature, canonicalHeaders, signedHeaders, payloadHash, base64, resp;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0: return [4 /*yield*/, this.encryptDocument({ document: document })];
                    case 1:
                        encryptedDocument = _c.sent();
                        edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
                        headers = {
                            created: Number(new Date()).toString(),
                            'content-type': 'application/json',
                            controller: this.verificationMethod.controller,
                            vermethodid: this.verificationMethod.id,
                            keyid: this.verificationMethod.id,
                            vermethoddid: this.verificationMethod.id,
                            algorithm: 'sha256-eth-personalSign',
                        };
                        hsEncDoc = new hsEncryptedDocument_1.default({ data: encryptedDocument, id: documentId, sequence: sequence });
                        body = hsEncDoc.get();
                        method = 'PUT';
                        return [4 /*yield*/, this.signRequest({
                                url: edvDocAddUrl,
                                method: 'PUT',
                                query: null,
                                keyId: this.verificationMethod.id,
                                headers: headers,
                                body: body,
                            })];
                    case 2:
                        _b = _c.sent(), signature = _b.signature, canonicalHeaders = _b.canonicalHeaders, signedHeaders = _b.signedHeaders, payloadHash = _b.payloadHash;
                        base64 = Buffer.from(signature.slice(2), 'hex').toString('base64');
                        headers['Authorization'] = "Signature keyId=\"".concat(this.verificationMethod.id, "\",algorithm=\"sha256-eth-personalSign\",headers=\"").concat(signedHeaders, "\",signature=\"").concat(base64, "\"");
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvDocAddUrl,
                                method: 'PUT',
                                body: body,
                                headers: headers,
                            })];
                    case 3:
                        resp = _c.sent();
                        return [2 /*return*/, resp];
                }
            });
        });
    };
    /**
     * Fetchs docs related to a particular documentId
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns all documents (with sequences if not passed) for a documentId
     */
    HypersignEdvClientEcdsaSecp256k1.prototype.fetchDoc = function (_a) {
        var documentId = _a.documentId, edvId = _a.edvId, sequence = _a.sequence;
        return __awaiter(this, void 0, void 0, function () {
            var edvDocAddUrl, resp;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document/' + documentId;
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvDocAddUrl,
                                method: 'GET',
                            })];
                    case 1:
                        resp = _b.sent();
                        return [2 /*return*/, resp];
                }
            });
        });
    };
    HypersignEdvClientEcdsaSecp256k1.prototype.decryptDocument = function (_a) {
        var encryptedDocument = _a.encryptedDocument;
        return __awaiter(this, void 0, void 0, function () {
            var accounts, encryptedMessage, decryptedMessage;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, window.ethereum.request({ method: 'eth_requestAccounts' })];
                    case 1:
                        accounts = _b.sent();
                        encryptedMessage = ethUtil.bufferToHex(Buffer.from(JSON.stringify(encryptedDocument)));
                        return [4 /*yield*/, window.ethereum.request({
                                method: 'eth_decrypt',
                                params: [encryptedMessage, accounts[0]],
                            })];
                    case 2:
                        decryptedMessage = _b.sent();
                        return [2 /*return*/, JSON.parse(decryptedMessage)];
                }
            });
        });
    };
    return HypersignEdvClientEcdsaSecp256k1;
}());
exports.default = HypersignEdvClientEcdsaSecp256k1;
