## Intro

The edv client converts `Ed25519VerificationKey2020` into `X25519KeyAgreementKey2020` key pair internally and use that for encryption and decryption. For signing, it uses `Ed25519VerificationKey2020` only. As a invoker/developer, they only need to worry about `Ed25519VerificationKey2020` pair. 

This package exposes three classes:
- `HypersignEdvClient` - for interacting with the [edv service](https://github.com/hypersign-protocol/hypersign-edv-service)
- `HypersignCipher` - for encryption and decryption
- `HypersignZCapHttpSigner` - for signing http/https authorization capabilities read/write)

## Install

```sh
git clone https://github.com/hypersign-protocol/hypersign-edv-client
cd hypersign-edv-client
npm i
```

## Build

```sh
npm run build
```

## Test

```sh
npm run test
```

## How to use

### Import the package

```js
import { HypersignEdvClient } from 'hypersign-edv-client';
```

### Create an EDV client instance

#### Generate a Ed25519Keypair

```js
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

const authenticationKey = {
  '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
  id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
  controller: 'did:test:controller',
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
  privateKeyMultibase: 'zrv2gheftP7VGPVoaJ7TbxGCN7pVXescn9FudB4xpF2HMWyjvzHuGVyPAb1NUeUGqqMxfHxgHiuLtR3pN5xyp8WLHR4',
};

const ed25519Keypair = await Ed25519VerificationKey2020.generate({ ...authenticationKey });
```
Note: For time being since we are not using any Key Management System (KMS), we expect client to manage the authentication key  somewhere secure. 


#### Prepare your keyresolver

A sample keyresolver. It can get more complex than this example. Like you want to call blockchain to fetch verification key.

// TODO: add description about keyresolver

```js
const keyResolver = async ({ id }) => {
  const authenticationKey = {
    '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
    id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
    controller: 'did:test:controller',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
    privateKeyMultibase: '',
  };
  const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519Keypair(authenticationKey);
  return ed25519KeyPair;
};
```

#### Initiate the EDV Client instance to interact with Hypersign edv service

```js
const hsEDVClient = new HypersignEdvClient({
  keyResolver,
  url, // URL of the data vault service i.e localhost:3001
  ed25519VerificationKey2020: ed25519Keypair,
});
```

### Register an EDV

```js
const config = {
  controller: 'did:example:123456789',
  keyAgreementKey: {
    id: 'https://example.com/kms/12345',
    type: 'X25519KeyAgreementKey2020',
  },
  hmac: {
    id: 'https://example.com/kms/67891',
    type: 'Sha256HmacKey2020',
  },
  edvId: 'my-edv-1', // Optional If `edvId` is not provided then the datavault will be created one.
};
const data = await hsEDVClient.registerEdv(config);
```

If the edvId already exists, then it will simply return the edv configuration without giving any error.

### Get an already registered edv

// TODO

## APIs

### Insert a Doc

```js
const edvId = data.id;
const m = { foo: 'bar' };
// Inserting a doc in edv
const res = await hsEDVClient.insertDoc({ document: m, edvId });
console.log(res);
```

If `documentId` is not provided then the datavault will be created one.

### Insert a Doc with custom id

```js
const edvId = data.id;
const m = { foo: 'bar' };
// Inserting a doc in edv
const res = await hsEDVClient.insertDoc({ document: m, documentId: 'my-doc-id-1', edvId });
console.log(res);
```

### Update Doc

```js
// updating a doc 1st time
m.foo = 'bar2';
const { id } = res;
const res2 = await hsEDVClient.updateDoc({ document: m, documentId: id, edvId });
console.log(res2);
```

### Update Doc with new sequence

```js
//updating a doc 2nd time with new sequence
m.foo = 'bar34';
const res4 = await hsEDVClient.updateDoc({ document: m, documentId: id, sequence: 1, edvId });
console.log(res4);
```

### Fetch Doc

```js
// Fetching a doc with doc id from edv:  it should return 2 docs
const res5 = await hsEDVClient.fetchDoc({ documentId: id, edvId });
console.log(res5);
```

## Credit:

This repo is inspired by https://github.com/digitalbazaar/edv-client repo. Big shout out to them who who has been working on helping user gain control of their identity and data.

XSalsa20-Poly1305 and 256-bit "AES-GCM" as the FIPS-compliant version.
https://www.npmjs.com/package/@digitalbazaar/minimal-cipher

## Caution

This repo is under development
