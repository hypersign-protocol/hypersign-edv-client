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
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("../index");
var key_spec_1 = require("./key.spec");
function createClient() {
    return __awaiter(this, void 0, void 0, function () {
        var url, ed25519Keypair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    url = 'http://localhost:3001';
                    return [4 /*yield*/, (0, key_spec_1.Ed25519Keypair)(key_spec_1.authenticationKey)];
                case 1:
                    ed25519Keypair = _a.sent();
                    return [2 /*return*/, new index_1.HypersignEdvClient({ keyResolver: key_spec_1.hypersignDIDKeyResolverForEd25519KeyPair, url: url, ed25519VerificationKey2020: ed25519Keypair })];
            }
        });
    });
}
function register() {
    return __awaiter(this, void 0, void 0, function () {
        var hsEDVClient, config, data, edvId, m, res, id, res2, res3, res4, res5;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, createClient()];
                case 1:
                    hsEDVClient = _a.sent();
                    config = {
                        controller: 'did:example:123456789',
                        keyAgreementKey: {
                            id: 'https://example.com/kms/12345',
                            type: 'X25519KeyAgreementKey2020',
                        },
                        hmac: {
                            id: 'https://example.com/kms/67891',
                            type: 'Sha256HmacKey2020',
                        },
                        edvId: "my-edv-1" // Optional 
                    };
                    return [4 /*yield*/, hsEDVClient.registerEdv(config)];
                case 2:
                    data = _a.sent();
                    console.log(data);
                    edvId = data.id;
                    console.log('New edvId is: ' + edvId);
                    m = { 'foo': 'bar' };
                    return [4 /*yield*/, hsEDVClient.insertDoc({ document: m, edvId: edvId })];
                case 3:
                    res = _a.sent();
                    console.log(res);
                    // updating a doc 1st time
                    m.foo = 'bar2';
                    id = res.id;
                    return [4 /*yield*/, hsEDVClient.updateDoc({ document: m, documentId: id, edvId: edvId })];
                case 4:
                    res2 = _a.sent();
                    console.log(res2);
                    //updating a doc 2nd time with same sequence (default will be 0)
                    m.foo = 'bar3';
                    return [4 /*yield*/, hsEDVClient.updateDoc({ document: m, documentId: id, edvId: edvId })];
                case 5:
                    res3 = _a.sent();
                    console.log(res3);
                    //updating a doc 3rd time with new sequence 
                    m.foo = 'bar34';
                    return [4 /*yield*/, hsEDVClient.updateDoc({ document: m, documentId: id, sequence: 1, edvId: edvId })];
                case 6:
                    res4 = _a.sent();
                    console.log(res4);
                    return [4 /*yield*/, hsEDVClient.fetchDoc({ documentId: id, edvId: edvId })];
                case 7:
                    res5 = _a.sent();
                    console.log(res5);
                    return [2 /*return*/];
            }
        });
    });
}
register();
