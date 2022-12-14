

## Intro
XSalsa20-Poly1305 and 256-bit "AES-GCM" as the FIPS-compliant version.

https://www.npmjs.com/package/@digitalbazaar/minimal-cipher

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


## How to use 

### Import the package
```js
import { HypersignEdvClient } from 'hypersign-edv-client';
```

### Create an EDV

```js
const hsEDVClient = new HypersignEdvClient({
    keyResolver, 
    url, 
    keyAgreementKey: keyAgreementKey});
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
  };
  const data  = await hsEDVClient.registerEdv(config);

```

### Insert a Doc

```js
const edvId = data.id;
const m = { 'foo': 'bar' };
const res = await hsEDVClient.insertDoc(m, edvId);
  
```

### Sample keyResolver
```js
const keyResolver = async ({id}) => {
    const authenticationKey = {
      '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
      id: 'did:test:controller#z6LSn4BWsAcep16pCKUW1h6g8HL18PZfSAxLMzBDQiEyEGur',
      controller: 'did:test:controller',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
      privateKeyMultibase: ""
    } 
    const ed25519KeyPair: Ed25519VerificationKey2020 = await Ed25519Keypair(authenticationKey);
    return ed25519KeyPair;
}

```

## Credit:

This repo is inspired by https://github.com/digitalbazaar/edv-client repo. Big shout out to them who who has been working on helping user gain control of their identity and data.




