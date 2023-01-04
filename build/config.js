"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Defaults = {
    edvsBaseURl: 'http://localhost:3001',
};
var APIs = {
    edvAPI: '/api/v1/edv',
    edvDocAPI: '/api/v1/edv/<EDVID>/document',
};
exports.default = {
    Defaults: Defaults,
    APIs: APIs,
};
