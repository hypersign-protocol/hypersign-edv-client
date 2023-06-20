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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.HypersignEdvClientEd25519VerificationKey2020 = void 0;
const config_1 = __importDefault(require("./config"));
const utils_1 = __importDefault(require("./utils"));
const hsEncryptedDocument_1 = __importDefault(require("./hsEncryptedDocument"));
const hsEdvDataModels_1 = require("./hsEdvDataModels");
const hsCipher_1 = __importDefault(require("./hsCipher"));
const hsZCapHttpSig_1 = __importDefault(require("./hsZCapHttpSig"));
const HypersignEdvClientEcdsaSecp256k1_1 = __importDefault(require("./HypersignEdvClientEcdsaSecp256k1"));
const Hmac_1 = __importDefault(require("./Hmac"));
const IndexHelper_1 = require("./IndexHelper");
class HypersignEdvClientEd25519VerificationKey2020 {
    constructor({ keyResolver, url, ed25519VerificationKey2020, x25519KeyAgreementKey2020, shaHmacKey2020, }) {
        // optional parameters
        this.edvsUrl = utils_1.default._sanitizeURL(url || config_1.default.Defaults.edvsBaseURl);
        this.keyResolver = keyResolver;
        this.ed25519VerificationKey2020 = ed25519VerificationKey2020;
        this.x25519KeyAgreementKey2020 = x25519KeyAgreementKey2020;
        this.hsCipher = new hsCipher_1.default({ keyResolver: this.keyResolver, keyAgreementKey: x25519KeyAgreementKey2020 });
        this.shaHmacKey2020 = shaHmacKey2020
            ? shaHmacKey2020
            : {
                id: ed25519VerificationKey2020.id,
                type: hsEdvDataModels_1.HmacKeyTypes.Sha256HmacKey2020,
                key: ed25519VerificationKey2020.privateKeyMultibase,
            };
        // always ed25519VerificationKey2020
        this.hsHttpSigner = new hsZCapHttpSig_1.default({ capabilityInvocationKey: this.ed25519VerificationKey2020 });
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
    registerEdv(config) {
        return __awaiter(this, void 0, void 0, function* () {
            const edvConfig = {};
            edvConfig.controller = config.controller;
            if (config.keyAgreementKey && !hsEdvDataModels_1.KeyAgreementKeyTypes[config.keyAgreementKey.type]) {
                throw new Error('Unsupported keyagreement type: ' + config.keyAgreementKey.type);
            }
            if (config.hmac && !hsEdvDataModels_1.HmacKeyTypes[config.hmac.type]) {
                throw new Error('Unsupported hmac type: ' + config.hmac.type);
            }
            // Adding support for custom id
            if (config.edvId) {
                edvConfig.id = config.edvId;
            }
            if (config.keyAgreementKey && config.hmac) {
                edvConfig.keyAgreementKey = {
                    id: config.keyAgreementKey.id,
                    type: hsEdvDataModels_1.KeyAgreementKeyTypes[config.keyAgreementKey.type],
                };
                edvConfig.hmac = {
                    id: config.hmac.id,
                    type: hsEdvDataModels_1.HmacKeyTypes[config.hmac.type],
                };
            }
            else {
                edvConfig.keyAgreementKey = {
                    id: this.x25519KeyAgreementKey2020.id,
                    type: hsEdvDataModels_1.KeyAgreementKeyTypes[this.x25519KeyAgreementKey2020.type],
                };
                edvConfig.hmac = {
                    id: this.shaHmacKey2020.id,
                    type: hsEdvDataModels_1.HmacKeyTypes[this.shaHmacKey2020.type],
                };
            }
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
            const edvRegisterURl = this.edvsUrl + config_1.default.APIs.edvAPI;
            const method = 'POST';
            const headers = {
                // digest signature
                // authorization header,
                controller: this.ed25519VerificationKey2020.controller,
                vermethodid: this.ed25519VerificationKey2020.id,
                date: new Date().toUTCString(),
            };
            const signedHeader = yield this.hsHttpSigner.signHTTP({
                url: edvRegisterURl,
                method,
                headers,
                encryptedObject: edvConfig,
                capabilityAction: 'write',
            });
            const resp = yield utils_1.default._makeAPICall({
                url: edvRegisterURl,
                method: 'POST',
                body: edvConfig,
                headers: signedHeader,
            });
            // attaching the newly created edv id
            edvConfig.id = resp.id;
            return edvConfig;
        });
    }
    /**
     * Inserts a new docs in the data vault
     * @param document doc to be updated in plain text
     * @param documentId Id of the document
     * @param edvId Id of the data vault
     * @param sequence Optional sequence number, default is 0
     * @returns updated document
     */
    insertDoc({ document, metadata, documentId, sequence, edvId, recipients, indexs, }) {
        return __awaiter(this, void 0, void 0, function* () {
            // encrypt the document
            let finalIndex;
            if (indexs) {
                const hmac = yield Hmac_1.default.create({
                    key: this.shaHmacKey2020.key,
                    id: this.shaHmacKey2020.id,
                });
                const indexDoc = new IndexHelper_1.IndexHelper();
                indexs.forEach((attr) => __awaiter(this, void 0, void 0, function* () {
                    indexDoc.ensureIndex({
                        attribute: attr.index,
                        unique: attr.unique,
                        hmac,
                    });
                }));
                finalIndex = yield indexDoc.createEntry({ doc: document, hmac });
            }
            const jwe = yield this.hsCipher.encryptObject({
                plainObject: document,
                recipients,
            });
            const hsEncDoc = new hsEncryptedDocument_1.default({ jwe, indexd: [finalIndex], id: documentId, metadata, sequence });
            // form the http request header by signing the header
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
            const headers = {
                // digest signature
                // authorization header,
                controller: this.ed25519VerificationKey2020.controller,
                vermethodid: this.ed25519VerificationKey2020.id,
                date: new Date().toUTCString(),
            };
            const method = 'POST';
            const signedHeader = yield this.hsHttpSigner.signHTTP({
                url: edvDocAddUrl,
                method,
                headers,
                encryptedObject: hsEncDoc.get(),
                capabilityAction: 'write',
            });
            // make the call to store
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method,
                body: hsEncDoc.get(),
                headers: signedHeader,
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
            // encrypt the document
            const jwe = yield this.hsCipher.encryptObject({
                plainObject: document,
            });
            const hsEncDoc = new hsEncryptedDocument_1.default({ jwe, id: documentId, metadata, sequence });
            // form the http request header by signing the header
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
            const headers = {
                // digest signature
                // authorization header,
                controller: this.ed25519VerificationKey2020.controller,
                vermethodid: this.ed25519VerificationKey2020.id,
                date: new Date().toUTCString(),
            };
            const method = 'PUT';
            const signedHeader = yield this.hsHttpSigner.signHTTP({
                url: edvDocAddUrl,
                method,
                headers,
                encryptedObject: hsEncDoc.get(),
                capabilityAction: 'write',
            });
            // make the call to store
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method,
                body: hsEncDoc.get(),
                headers: signedHeader,
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
            const signedHeader = yield this.hsHttpSigner.signHTTP({
                url: edvDocAddUrl,
                method,
                headers,
                encryptedObject: undefined,
                capabilityAction: 'read',
            });
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'GET',
                headers: signedHeader,
            });
            return resp;
        });
    }
    getEdvConfig(edvId) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Method not implemented');
        });
    }
    fetchAllDocs({ edvId, limit, page }) {
        return __awaiter(this, void 0, void 0, function* () {
            const edvDocAddUrl = this.edvsUrl + config_1.default.APIs.edvAPI + '/' + edvId + '/document';
            const method = 'GET';
            const headers = {
                // digest signature
                // authorization header,
                controller: this.ed25519VerificationKey2020.controller,
                vermethodid: this.ed25519VerificationKey2020.id,
                date: new Date().toUTCString(),
            };
            const signedHeader = yield this.hsHttpSigner.signHTTP({
                url: edvDocAddUrl,
                method,
                headers,
                encryptedObject: undefined,
                capabilityAction: 'read',
            });
            const resp = yield utils_1.default._makeAPICall({
                url: edvDocAddUrl,
                method: 'GET',
                headers: signedHeader,
            });
            return resp;
        });
    }
    deleteDoc({ documentId }) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('Method not implemented');
        });
    }
}
exports.HypersignEdvClientEd25519VerificationKey2020 = HypersignEdvClientEd25519VerificationKey2020;
var invocationType;
(function (invocationType) {
    invocationType["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020";
    invocationType["HypersignEdvClientEcdsaSecp256k1"] = "HypersignEdvClientEcdsaSecp256k1";
})(invocationType || (invocationType = {}));
var keyagreementType;
(function (keyagreementType) {
    keyagreementType["X25519KeyAgreementKey2020"] = "X25519KeyAgreementKey2020";
    keyagreementType["X25519KeyAgreementKeyEIP5630"] = "X25519KeyAgreementKeyEIP5630";
})(keyagreementType || (keyagreementType = {}));
function HypersignEdvClient(params) {
    // : HypersignEdvClientEcdsaSecp256k1 | HypersignEdvClientEd25519VerificationKey2020
    if (!params.url)
        throw new Error('edvsUrl is required');
    if (!params.invocationKeyPair)
        throw new Error('InvocationKeyPair is required');
    if (!params.keyagreementKeyPair)
        throw new Error('KeyAgreementKeyPair is required');
    if (!params.invocationKeyPair.id)
        throw new Error('InvocationKeyPair.id is required');
    if (!params.invocationKeyPair.type)
        throw new Error('InvocationKeyPair.type is required');
    if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 && !params.invocationKeyPair.publicKeyMultibase)
        throw new Error('InvocationKeyPair.publicKeyMultibase is required');
    if (params.invocationKeyPair.type === invocationType.HypersignEdvClientEcdsaSecp256k1 &&
        !params.invocationKeyPair.blockchainAccountId)
        throw new Error('InvocationKeyPair.blockchainAccountId is required');
    if (!params.keyagreementKeyPair.id)
        throw new Error('KeyAgreementKeyPair.id is required');
    if (!params.keyagreementKeyPair.type)
        throw new Error('KeyAgreementKeyPair.type is required');
    if (params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020 &&
        !params.keyagreementKeyPair.publicKeyMultibase)
        throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
    if (params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKeyEIP5630 &&
        !params.keyagreementKeyPair.publicKeyMultibase)
        throw new Error('KeyAgreementKeyPair.publicKeyMultibase is required');
    if (params.invocationKeyPair.type === invocationType.Ed25519VerificationKey2020 &&
        params.keyagreementKeyPair.type === keyagreementType.X25519KeyAgreementKey2020) {
        if (!params.keyResolver)
            throw new Error('keyResolver is required');
        return new HypersignEdvClientEd25519VerificationKey2020({
            url: params.url,
            ed25519VerificationKey2020: params.invocationKeyPair,
            x25519KeyAgreementKey2020: params.keyagreementKeyPair,
            keyResolver: params.keyResolver,
            shaHmacKey2020: params.shaHmacKey2020,
        });
    }
    else {
        return new HypersignEdvClientEcdsaSecp256k1_1.default({
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
exports.default = HypersignEdvClient;
