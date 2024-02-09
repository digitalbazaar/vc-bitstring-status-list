/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import suiteCtx2020 from 'ed25519-signature-2020-context';
import {
  CONTEXT_URL as VC_BSL_V1_CONTEXT_URL
} from '@digitalbazaar/vc-bitstring-status-list-context';

const SUITE_CONTEXT_URL = suiteCtx2020.constants.CONTEXT_URL;

const encodedList100KWith50KthRevoked =
  'H4sIAAAAAAAAA-3OMQ0AAAgDsOHfNB72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFrc4zDz' +
  'UMAAA';

export const slCredentialRevocation = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    VC_BSL_V1_CONTEXT_URL,
    SUITE_CONTEXT_URL
  ],
  id: 'https://example.com/status/1',
  issuer: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop',
  issuanceDate: '2022-06-02T16:00:21Z',
  type: [ 'VerifiableCredential', 'BitstringStatusListCredential' ],
  credentialSubject: {
    id: 'https://example.com/status/1#list',
    type: 'BitstringStatusList',
    encodedList: encodedList100KWith50KthRevoked,
    statusPurpose: 'revocation'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2024-02-09T06:43:18Z',
    verificationMethod: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5U' +
      'jBop#z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop',
    proofPurpose: 'assertionMethod',
    proofValue: 'z5R731MjeqiZdMrbUCTu9eKMZ1MQbdzVBH6h3poSK6v2m5qGWQsTym3FFHuy' +
      '13PGqnJpRiARZ9jkXSi7CMxkySo3E'
  }
};

export const slCredentialSuspension = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    VC_BSL_V1_CONTEXT_URL,
    SUITE_CONTEXT_URL
  ],
  id: 'https://example.com/status/2',
  issuer: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop',
  issuanceDate: '2022-06-02T16:06:22Z',
  type: [ 'VerifiableCredential', 'BitstringStatusListCredential' ],
  credentialSubject: {
    id: 'https://example.com/status/2#list',
    type: 'BitstringStatusList',
    encodedList: encodedList100KWith50KthRevoked,
    statusPurpose: 'suspension'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2024-02-09T06:43:18Z',
    verificationMethod: 'did:key:z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5' +
      'UjBop#z6MkowtnRyMkCerXvXqjCYUo2mLEeCgX1sWfoP2CZA5UjBop',
    proofPurpose: 'assertionMethod',
    proofValue: 'z5DvJ59aVSb3QkhWvhVWXcjfhk4CLhDfvcusMDaLky7dmSJNEbf3WLxXPzP' +
      'wcMFVZ2StM1xrPc99ashXFeWhhh7Co'
  }
};
