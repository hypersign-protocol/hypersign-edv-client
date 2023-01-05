"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
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
var hsCipher_1 = __importDefault(require("./hsCipher"));
var hsZCapHttpSig_1 = __importDefault(require("./hsZCapHttpSig"));
var HypersignEdvClient = /** @class */ (function () {
    function HypersignEdvClient(_a) {
        var keyResolver = _a.keyResolver, url = _a.url, ed25519VerificationKey2020 = _a.ed25519VerificationKey2020;
        // optional parameters
        this.edvsUrl = utils_1.default._sanitizeURL(url || config_1.default.Defaults.edvsBaseURl);
        this.keyResolver = keyResolver;
        this.ed25519VerificationKey2020 = ed25519VerificationKey2020;
        this.hsCipher = new hsCipher_1.default({ keyResolver: this.keyResolver, keyAgreementKey: this.ed25519VerificationKey2020 });
        this.hsHttpSigner = new hsZCapHttpSig_1.default({ keyAgreementKey: this.ed25519VerificationKey2020 });
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
    HypersignEdvClient.prototype.registerEdv = function (config) {
        return __awaiter(this, void 0, void 0, function () {
            var edvConfig, edvRegisterURl, resp;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        edvConfig = {};
                        edvConfig.controller = config.controller;
                        if (!hsEdvDataModels_1.KeyAgreementKeyTypes[config.keyAgreementKey.type]) {
                            throw new Error('Unsupported keyagreement type: ' + config.keyAgreementKey.type);
                        }
                        if (!hsEdvDataModels_1.HmacKeyTypes[config.hmac.type]) {
                            throw new Error('Unsupported hmac type: ' + config.hmac.type);
                        }
                        // Adding support for custom id
                        if (config.edvId) {
                            edvConfig.id = config.edvId;
                        }
                        edvConfig.keyAgreementKey = {
                            id: config.keyAgreementKey.id,
                            type: hsEdvDataModels_1.KeyAgreementKeyTypes[config.keyAgreementKey.type],
                        };
                        edvConfig.hmac = {
                            id: config.hmac.id,
                            type: hsEdvDataModels_1.HmacKeyTypes[config.hmac.type],
                        };
                        edvConfig.sequence = 0; // default values
                        edvConfig.referenceId = 'primary'; // default values
                        edvConfig.invoker = config.controller; // default values
                        edvConfig.delegator = config.controller; // default values
                        if (config.invoker)
                            edvConfig.invoker = config.invoker;
                        if (config.referenceId)
                            edvConfig.referenceId = config.referenceId;
                        if (config.delegator)
                            edvConfig.delegator = config.delegator;
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
    /**
     * Inserts a new docs in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns updated document
     */
    HypersignEdvClient.prototype.insertDoc = function (_a) {
        var document = _a.document, documentId = _a.documentId, sequence = _a.sequence, edvId = _a.edvId;
        return __awaiter(this, void 0, void 0, function () {
            var jwe, hsEncDoc, edvDocAddUrl, headers, method, signedHeader, resp;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, this.hsCipher.encryptObject({
                            plainObject: document,
                        })];
                    case 1:
                        jwe = _b.sent();
                        hsEncDoc = new hsEncryptedDocument_1.default({ jwe: jwe, id: documentId, sequence: sequence });
                        edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
                        headers = {
                            // digest signature
                            // authorization header,
                            controller: this.ed25519VerificationKey2020.controller,
                            vermethodid: this.ed25519VerificationKey2020.id,
                            date: new Date().toUTCString(),
                        };
                        method = 'POST';
                        return [4 /*yield*/, this.hsHttpSigner.signHTTP({
                                url: edvDocAddUrl,
                                method: method,
                                headers: headers,
                                encryptedObject: hsEncDoc.get(),
                                capabilityAction: 'write',
                            })];
                    case 2:
                        signedHeader = _b.sent();
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvDocAddUrl,
                                method: method,
                                body: hsEncDoc.get(),
                                headers: signedHeader,
                            })];
                    case 3:
                        resp = _b.sent();
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
    HypersignEdvClient.prototype.updateDoc = function (_a) {
        var document = _a.document, documentId = _a.documentId, sequence = _a.sequence, edvId = _a.edvId;
        return __awaiter(this, void 0, void 0, function () {
            var jwe, hsEncDoc, edvDocAddUrl, headers, method, signedHeader, resp;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, this.hsCipher.encryptObject({
                            plainObject: document,
                        })];
                    case 1:
                        jwe = _b.sent();
                        hsEncDoc = new hsEncryptedDocument_1.default({ jwe: jwe, id: documentId, sequence: sequence });
                        edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
                        headers = {
                            // digest signature
                            // authorization header,
                            controller: this.ed25519VerificationKey2020.controller,
                            vermethodid: this.ed25519VerificationKey2020.id,
                            date: new Date().toUTCString(),
                        };
                        method = 'PUT';
                        return [4 /*yield*/, this.hsHttpSigner.signHTTP({
                                url: edvDocAddUrl,
                                method: method,
                                headers: headers,
                                encryptedObject: hsEncDoc.get(),
                                capabilityAction: 'write',
                            })];
                    case 2:
                        signedHeader = _b.sent();
                        return [4 /*yield*/, utils_1.default._makeAPICall({
                                url: edvDocAddUrl,
                                method: method,
                                body: hsEncDoc.get(),
                                headers: signedHeader,
                            })];
                    case 3:
                        resp = _b.sent();
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
    HypersignEdvClient.prototype.fetchDoc = function (_a) {
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
    HypersignEdvClient.prototype.getEdvConfig = function (edvId) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                throw new Error('Method not implemented');
            });
        });
    };
    HypersignEdvClient.prototype.fetchAllDocs = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                throw new Error('Method not implemented');
            });
        });
    };
    HypersignEdvClient.prototype.deleteDoc = function (_a) {
        var documentId = _a.documentId;
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_b) {
                console.log({ documentId: documentId });
                throw new Error('Method not implemented');
            });
        });
    };
    return HypersignEdvClient;
}());
exports.default = HypersignEdvClient;
