/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {issue} from '@digitalbazaar/vc';
import suiteCtx2020 from 'ed25519-signature-2020-context';

const SUITE_CONTEXT_URL = suiteCtx2020.constants.CONTEXT_URL;

const encodedList100KWith50KthRevoked =
  'uH4sIAAAAAAAAA-3OMQ0AAAgDsOHfNB72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFrc4zDz' +
  'UMAAA';

export async function createMockBitstringStatusListCredential({
  id, suite, statusPurpose, documentLoader
}) {
  if(!id) {
    id = 'https://example.com/status/1';
  }
  if(!suite) {
    const keyPair = await Ed25519VerificationKey2020.generate();
    const {publicKeyMultibase} = keyPair;
    keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
    keyPair.controller = `did:key:${publicKeyMultibase}`;
    suite = new Ed25519Signature2020({key: keyPair});
  }
  const credential = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      SUITE_CONTEXT_URL
    ],
    id,
    issuer: suite.key.controller,
    validFrom: '2022-06-02T16:00:21Z',
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    credentialSubject: {
      id: `${id}#list`,
      type: 'BitstringStatusList',
      encodedList: encodedList100KWith50KthRevoked,
      statusPurpose
    }
  };
  return issue({credential, suite, documentLoader});
}
