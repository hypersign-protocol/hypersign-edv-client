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
var minimal_cipher_1 = require("@digitalbazaar/minimal-cipher");
var x25519_key_agreement_key_2020_1 = require("@digitalbazaar/x25519-key-agreement-key-2020");
var hsEdvDataModels_1 = require("./hsEdvDataModels");
var ed25519_verification_key_2020_1 = require("@digitalbazaar/ed25519-verification-key-2020");
var HypersignCipher = /** @class */ (function () {
    function HypersignCipher(_a) {
        var keyResolver = _a.keyResolver, keyAgreementKey = _a.keyAgreementKey;
        this.keyResolver = keyResolver;
        this.cipher = new minimal_cipher_1.Cipher();
        this.keyAgreementKey = keyAgreementKey;
    }
    HypersignCipher.prototype._getX25519KeyAgreementKey = function (keyAgreementKey) {
        if (keyAgreementKey === void 0) { keyAgreementKey = this.keyAgreementKey; }
        return __awaiter(this, void 0, void 0, function () {
            var ed25519KeyPair, keyAgreementKeyPair;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!(keyAgreementKey.type === hsEdvDataModels_1.VerificationKeyTypes.Ed25519VerificationKey2020)) return [3 /*break*/, 2];
                        return [4 /*yield*/, ed25519_verification_key_2020_1.Ed25519VerificationKey2020.generate(__assign({}, keyAgreementKey))];
                    case 1:
                        ed25519KeyPair = _a.sent();
                        keyAgreementKeyPair = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
                            keyPair: ed25519KeyPair,
                        });
                        return [2 /*return*/, keyAgreementKeyPair];
                    case 2:
                        if (keyAgreementKey.type === hsEdvDataModels_1.KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
                            return [2 /*return*/, keyAgreementKey];
                        }
                        else {
                            throw new Error('Unsupported type  ' + keyAgreementKey.type);
                        }
                        _a.label = 3;
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    // TODO: bas way of doing it
    HypersignCipher.prototype._getX25519KeyAgreementResolver = function (keyResolver, id) {
        if (keyResolver === void 0) { keyResolver = this.keyResolver; }
        return __awaiter(this, void 0, void 0, function () {
            var keypairObj, keyAgreementKeyPair_1;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, keyResolver({ id: id })];
                    case 1:
                        keypairObj = _a.sent();
                        if (keypairObj.type === hsEdvDataModels_1.VerificationKeyTypes.Ed25519VerificationKey2020) {
                            keyAgreementKeyPair_1 = x25519_key_agreement_key_2020_1.X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
                                keyPair: keypairObj,
                            });
                            return [2 /*return*/, function () { return __awaiter(_this, void 0, void 0, function () {
                                    return __generator(this, function (_a) {
                                        return [2 /*return*/, keyAgreementKeyPair_1];
                                    });
                                }); }];
                        }
                        else if (keypairObj.type === hsEdvDataModels_1.KeyAgreementKeyTypes.X25519KeyAgreementKey2020) {
                            return [2 /*return*/, keyResolver];
                        }
                        else {
                            throw new Error('Unsupported type  ' + keypairObj.type);
                        }
                        return [2 /*return*/];
                }
            });
        });
    };
    // helper to create default recipients
    HypersignCipher.prototype._createDefaultRecipients = function (keyAgreementKey) {
        return keyAgreementKey
            ? [
                {
                    header: {
                        kid: keyAgreementKey.id,
                        // only supported algorithm
                        alg: 'ECDH-ES+A256KW',
                    },
                },
            ]
            : [];
    };
    HypersignCipher.prototype.encryptObject = function (_a) {
        var plainObject = _a.plainObject, _b = _a.recipients, recipients = _b === void 0 ? [] : _b, _c = _a.keyResolver, keyResolver = _c === void 0 ? this.keyResolver : _c, _d = _a.keyAgreementKey, keyAgreementKey = _d === void 0 ? this.keyAgreementKey : _d;
        return __awaiter(this, void 0, void 0, function () {
            var x25519keyAgreementKey, kr, jwe;
            return __generator(this, function (_e) {
                switch (_e.label) {
                    case 0: return [4 /*yield*/, this._getX25519KeyAgreementKey(keyAgreementKey)];
                    case 1:
                        x25519keyAgreementKey = _e.sent();
                        // If not rece
                        if (recipients.length === 0 && x25519keyAgreementKey) {
                            recipients = this._createDefaultRecipients(x25519keyAgreementKey);
                        }
                        return [4 /*yield*/, this._getX25519KeyAgreementResolver(keyResolver, x25519keyAgreementKey.id)];
                    case 2:
                        kr = _e.sent();
                        return [4 /*yield*/, this.cipher.encryptObject({ obj: plainObject, recipients: recipients, keyResolver: kr })];
                    case 3:
                        jwe = _e.sent();
                        return [2 /*return*/, jwe];
                }
            });
        });
    };
    HypersignCipher.prototype.decryptObject = function (_a) {
        var jwe = _a.jwe, _b = _a.keyAgreementKey, keyAgreementKey = _b === void 0 ? this.keyAgreementKey : _b;
        return __awaiter(this, void 0, void 0, function () {
            var x25519keyAgreementKey, object;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0: return [4 /*yield*/, this._getX25519KeyAgreementKey(keyAgreementKey)];
                    case 1:
                        x25519keyAgreementKey = _c.sent();
                        return [4 /*yield*/, this.cipher.decryptObject({ jwe: jwe, keyAgreementKey: x25519keyAgreementKey })];
                    case 2:
                        object = _c.sent();
                        return [2 /*return*/, object];
                }
            });
        });
    };
    return HypersignCipher;
}());
exports.default = HypersignCipher;
