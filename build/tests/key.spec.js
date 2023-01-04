"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
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
exports.hypersignDIDKeyResolverForX25519KeyPair = exports.hypersignDIDKeyResolverForEd25519KeyPair = exports.X25519KeyAgreementKeyPair = exports.Ed25519Keypair = exports.authenticationKey = void 0;
var x25519_key_agreement_key_2020_1 = require("@digitalbazaar/x25519-key-agreement-key-2020");
var ed25519_verification_key_2020_1 = require("@digitalbazaar/ed25519-verification-key-2020");
exports.authenticationKey = {
    '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
    id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
    controller: 'did:test:controller',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
    privateKeyMultibase: 'zrv2gheftP7VGPVoaJ7TbxGCN7pVXescn9FudB4xpF2HMWyjvzHuGVyPAb1NUeUGqqMxfHxgHiuLtR3pN5xyp8WLHR4'
};
function Ed25519Keypair(key) {
    if (key === void 0) { key = exports.authenticationKey; }
    return __awaiter(this, void 0, void 0, function () {
        var ed25519KeyPair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, ed25519_verification_key_2020_1.Ed25519VerificationKey2020.generate(__assign({}, key))];
                case 1:
                    ed25519KeyPair = _a.sent();
                    return [2 /*return*/, ed25519KeyPair];
            }
        });
    });
}
exports.Ed25519Keypair = Ed25519Keypair;
function X25519KeyAgreementKeyPair(key) {
    if (key === void 0) { key = exports.authenticationKey; }
    return __awaiter(this, void 0, void 0, function () {
        var ed25519KeyPair;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, ed25519_verification_key_2020_1.Ed25519VerificationKey2020.generate(__assign({}, key))];
                case 1:
                    ed25519KeyPair = _a.sent();
                    // Finally we can convert into X25519KeyAgreementKey2020
                    return [2 /*return*/, x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair: ed25519KeyPair })];
            }
        });
    });
}
exports.X25519KeyAgreementKeyPair = X25519KeyAgreementKeyPair;
var hypersignDIDKeyResolverForEd25519KeyPair = function (_a) {
    var id = _a.id;
    return __awaiter(void 0, void 0, void 0, function () {
        var authenticationKey, ed25519KeyPair;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    authenticationKey = {
                        '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
                        id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
                        controller: 'did:test:controller',
                        type: 'Ed25519VerificationKey2020',
                        publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
                        privateKeyMultibase: ""
                    };
                    return [4 /*yield*/, Ed25519Keypair(authenticationKey)];
                case 1:
                    ed25519KeyPair = _b.sent();
                    return [2 /*return*/, ed25519KeyPair];
            }
        });
    });
};
exports.hypersignDIDKeyResolverForEd25519KeyPair = hypersignDIDKeyResolverForEd25519KeyPair;
// It takes verificaiton method as input and returns 
// This method will not have privat ekey.
var hypersignDIDKeyResolverForX25519KeyPair = function (_a) {
    var id = _a.id;
    return __awaiter(void 0, void 0, void 0, function () {
        var authenticationKey, keyAgreementKeyPair;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    authenticationKey = {
                        '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
                        id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
                        controller: 'did:test:controller',
                        type: 'Ed25519VerificationKey2020',
                        publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
                        privateKeyMultibase: ""
                    };
                    return [4 /*yield*/, X25519KeyAgreementKeyPair(authenticationKey)];
                case 1:
                    keyAgreementKeyPair = _b.sent();
                    return [2 /*return*/, keyAgreementKeyPair
                        // // Use veres driver to fetch the authn key directly
                        // const keyPair = await Ed25519VerificationKey2020.from(await veresDriver.get({did: id}));
                        // // Convert authn key to key agreement key
                        // return X25519KeyPair.fromEd25519VerificationKey2020({keyPair});
                    ];
            }
        });
    });
};
exports.hypersignDIDKeyResolverForX25519KeyPair = hypersignDIDKeyResolverForX25519KeyPair;
