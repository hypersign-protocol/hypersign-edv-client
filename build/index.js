"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Types = exports.HypersignEdvClientEd25519VerificationKey2020 = exports.IndexHelper = exports.Hmac = exports.HypersignEdvClientEcdsaSecp256k1 = exports.HypersignZCapHttpSigner = exports.HypersignCipher = exports.HypersignEdvClient = void 0;
const hsEdvClient_1 = __importDefault(require("./hsEdvClient"));
exports.HypersignEdvClient = hsEdvClient_1.default;
const HypersignEdvClientEd25519VerificationKey2020_1 = __importDefault(require("./HypersignEdvClientEd25519VerificationKey2020"));
exports.HypersignEdvClientEd25519VerificationKey2020 = HypersignEdvClientEd25519VerificationKey2020_1.default;
const hsCipher_1 = __importDefault(require("./hsCipher"));
exports.HypersignCipher = hsCipher_1.default;
const hsZCapHttpSig_1 = __importDefault(require("./hsZCapHttpSig"));
exports.HypersignZCapHttpSigner = hsZCapHttpSig_1.default;
const HypersignEdvClientEcdsaSecp256k1_1 = __importDefault(require("./HypersignEdvClientEcdsaSecp256k1"));
exports.HypersignEdvClientEcdsaSecp256k1 = HypersignEdvClientEcdsaSecp256k1_1.default;
const Types = __importStar(require("./Types"));
exports.Types = Types;
const IndexHelper_1 = require("./IndexHelper");
Object.defineProperty(exports, "IndexHelper", { enumerable: true, get: function () { return IndexHelper_1.IndexHelper; } });
const Hmac_1 = __importDefault(require("./Hmac"));
exports.Hmac = Hmac_1.default;
