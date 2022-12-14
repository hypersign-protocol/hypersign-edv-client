// import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';

export async function getEd25519KeyPair() {
  const keyId = 'did:key:foo';
  const controller = 'did:test:controller';
  const _id = `${keyId}:12312312312`;
  const kp = await Ed25519VerificationKey2020.generate({ controller, id: _id });
  return kp;
}

export async function getKP() {
  const vermethod = {
    id: 'did:key:foo:12312312312',
    controller: 'did:test:controller',
    revoked: undefined,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: 'z6MkozgYt1TTsTyWKWZZG2foaT4isAPGsYPotAdU6RJob9Ez',
    privateKeyMultibase: 'zrv2gheftP7VGPVoaJ7TbxGCN7pVXescn9FudB4xpF2HMWyjvzHuGVyPAb1NUeUGqqMxfHxgHiuLtR3pN5xyp8WLHR4',
  };

  const kp = await Ed25519VerificationKey2020.from({ ...vermethod });
  return kp;
}
