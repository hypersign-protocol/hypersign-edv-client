"use strict";
/**
 * Copyright (c) 2022, Hypermine Pvt. Ltd.
 * All rights reserved.
 * Author: Vishwas Anand Bhushan (Github @ vishwas1)
 */
Object.defineProperty(exports, "__esModule", { value: true });
const Defaults = {
    edvsBaseURl: 'http://localhost:3001',
};
const APIs = {
    edvAPI: '/api/v1/edv',
    edvDocAPI: '/api/v1/edv/<EDVID>/document',
};
exports.default = {
    Defaults,
    APIs,
};
