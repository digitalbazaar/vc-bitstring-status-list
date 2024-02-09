import {issue as vcIssueCredential} from '@digitalbazaar/vc';

import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {
  Ed25519Signature2020
} from '@digitalbazaar/ed25519-signature-2020';
const encodedList100KWith50KthRevoked =
  'H4sIAAAAAAAAA-3OMQ0AAAgDsOHfNB72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFrc4zDz' +
  'UMAAA';
export const createVC = async (documentLoader) => {
  const keyPair = await Ed25519VerificationKey2020.generate();
  const issuer = `did:key:${keyPair.publicKeyMultibase}`;
  keyPair.id = `did:key:${keyPair.publicKeyMultibase}#${keyPair.publicKeyMultibase}`;
  const suite = new Ed25519Signature2020({key: keyPair});
  const revCred = {
    "@context":[
       "https://www.w3.org/2018/credentials/v1",
       "https://www.w3.org/ns/credentials/status/v1",
       "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id":"https://example.com/status/1",
    "issuer":issuer,
    "issuanceDate":"2022-06-02T16:00:21Z",
    "type":[
       "VerifiableCredential",
       "BitstringStatusListCredential"
    ],
    "credentialSubject":{
       "id":"https://example.com/status/1#list",
       "type":"BitstringStatusList",
       "encodedList":encodedList100KWith50KthRevoked,
       "statusPurpose":"revocation"
    }
  };
  const revVC = await vcIssueCredential({credential: revCred, suite, documentLoader})
  console.log('revocation', revVC)
  const susCred = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      "https://www.w3.org/ns/credentials/status/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    id: 'https://example.com/status/2',
    issuer,
    issuanceDate: '2022-06-02T16:06:22Z',
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    credentialSubject: {
      id: 'https://example.com/status/2#list',
      type: 'BitstringStatusList',
      encodedList: encodedList100KWith50KthRevoked,
      statusPurpose: 'suspension'
    }
  };
  const susVC = await vcIssueCredential({credential: susCred, suite, documentLoader})
  console.log('susVC', susVC)
};
