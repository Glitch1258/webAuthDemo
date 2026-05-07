/**
 * Copyright 2022 Google LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { html, render, $, showSnackbar, loading, _fetch } from './util';
import { WebAuthnRegistrationObject, WebAuthnAuthenticationObject, UserInfo, AAGUIDs } from './common';
import { base64url } from './base64url';
import { MDCRipple } from '@material/ripple';
import { initializeApp } from 'firebase/app';
import { Checkbox } from '@material/mwc-checkbox';
import cbor from 'cbor';
import * as firebaseui from 'firebaseui';
import {
  getAuth,
  connectAuthEmulator,
  GoogleAuthProvider,
  onAuthStateChanged,
  User
} from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator } from 'firebase/firestore';
import { getFunctions, connectFunctionsEmulator } from 'firebase/functions';
import { getStorage, connectStorageEmulator } from 'firebase/storage';
import { getAnalytics } from 'firebase/analytics';
import {
  RegistrationCredential,
  RegistrationResponseJSON,
  AuthenticationCredential,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
} from '@simplewebauthn/types';
import { IconButton } from '@material/mwc-icon-button';
import { StoredCredential } from './common';

const aaguids = await fetch('/webauthn/aaguids').then(res => res.json());

// ============================================================
// FULLY LOCAL FIREBASE CONFIG - Uses ONLY local emulators
// ============================================================
const app = initializeApp({
  projectId: "demo-webauthn",  // "demo-" prefix tells Firebase to use emulators
  apiKey: "fake-api-key-for-local-dev",
  authDomain: "localhost",
  storageBucket: "localhost",
});

// Connect to ALL local emulators
const auth = getAuth();
const db = getFirestore(app);
const functions = getFunctions(app);
const storage = getStorage(app);

// Only connect to emulators when running locally
if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
  connectAuthEmulator(auth, 'http://localhost:9099');
  connectFirestoreEmulator(db, 'localhost', 8080);
  connectFunctionsEmulator(functions, 'localhost', 5001);
  connectStorageEmulator(storage, 'localhost', 9199);
}

// Note: Analytics doesn't work with emulators, but it won't break anything
// getAnalytics(app);  // Commented out - would try to contact real Firebase

const ui = new firebaseui.auth.AuthUI(auth);
const icon = $('#user-icon');
const transportIconMap = {
  internal: "devices",
  usb: "usb",
  nfc: "nfc",
  ble: "bluetooth",
  cable: "cable",
  hybrid: "cable",
} as { [key: string]: string };

/**
 *  Verify ID Token received via Firebase Auth
 * @param authResult 
 * @returns always return `false`
 */
const verifyIdToken = async (user: User): Promise<UserInfo> => {
  const id_token = await user.getIdToken();
  return await _fetch('/auth/verify', { id_token });
}

/**
 * Display Firebase Auth UI
 */
const displaySignin = () => {
  loading.start();
  ui.start('#firebaseui-auth-container', {
    signInOptions: [ GoogleAuthProvider.PROVIDER_ID ],
    signInFlow: 'popup',
    callbacks: { signInSuccessWithAuthResult: () => false, }
  });
  $('#dialog').show();
};

/**
 * Sign out from Firebase Auth
 */
const onSignout = async (e: any) => {
  if (!confirm('Do you want to sign out?')) {
    e.stopPropagation();
    return;
  }
  $('#user-info').close();
  await auth.signOut();
  await _fetch('/auth/signout');
  icon.innerText = '';
  icon.setAttribute('icon', 'account_circle');
  $('#drawer').open = false;
  $('#credentials').innerText = '';
  showSnackbar('You are signed out.');
  displaySignin();
};

/**
 * Invoked when Firebase Auth status is changed.
 */
onAuthStateChanged(auth, async token => {
  if (!window.PublicKeyCredential) {
    render(html`
      <p>Your browser does not support WebAuthn.</p>
    `, $('#firebaseui-auth-container'));
    $('#dialog').show();
    return false;
  }

  let user: UserInfo;

  if (token) {
    // When signed in.
    try {
      user = await verifyIdToken(token);

      // User Info is stored in the local storage.
      // This will be deleted when signing out.
      const _userInfo = localStorage.getItem('userInfo');
      // If there's already stored user info, fill the User Info dialog with them.
      if (!_userInfo) {
        // If there's no previous user info, store the current user info.
        localStorage.setItem('userInfo', JSON.stringify(user));
        $('#username').value = user.name;
        $('#display-name').value = user.displayName;
        $('#picture-url').value = user.picture;
      } else {
        // If there's user info in the local storage, use it.
        const userInfo = JSON.parse(_userInfo);
        $('#username').value = userInfo.name;
        $('#display-name').value = userInfo.displayName;
        $('#picture-url').value = userInfo.picture;
      }
    } catch (error) {
      console.error(error);
      showSnackbar('Sign-in failed.');
      return false;
    };

  } else {
    // When signed out.
    try {
      user = await _fetch('/auth/userInfo');
    } catch {
      // Signed out
      displaySignin();
      return false;
    }
  }
  $('#dialog').close();
  icon.removeAttribute('icon');
  render(html`<img src="${user.picture}">`, icon);
  showSnackbar('You are signed in!');
  loading.stop();
  listCredentials();
  return true;
});

/**
 *  Collect advanced options and return a JSON object.
 * @returns WebAuthnRegistrationObject
 */
const collectOptions = (
  mode: 'registration' | 'authentication' = 'registration'
): WebAuthnRegistrationObject|WebAuthnAuthenticationObject => {
  // const specifyCredentials = $('#switch-rr').checked;
  const authenticatorAttachment = $('#attachment').value;
  const attestation = $('#conveyance').value;
  const residentKey = $('#resident-key').value;
  const userVerification = $('#user-verification').value;
  const hints = [
    ...$('#hints1').value?[$('#hints1').value]:[],
    ...$('#hints2').value?[$('#hints2').value]:[],
    ...$('#hints3').value?[$('#hints3').value]:[],
  ];
  const credProps = $('#switch-cred-props').checked || false;
  const tasSwitch = $('#switch-tx-auth-simple').checked || undefined;
  const tas = $('#tx-auth-simple').value.trim() || undefined;
  const customTimeout = parseInt($('#custom-timeout').value);
  // const abortTimeout = parseInt($('#abort-timeout').value);

  let txAuthSimple;
  // Simple Transaction Authorization extension
  if (tasSwitch) {
    txAuthSimple = tas ?? undefined;
  }

  // This is registration
  if (mode === 'registration') {
    const userInfo = localStorage.getItem('userInfo');
    const user = userInfo ? JSON.parse(userInfo) : undefined;

    return {
      attestation,
      authenticatorSelection: {
        authenticatorAttachment,
        userVerification,
        residentKey
      },
      extensions: { credProps, },
      customTimeout,
      hints,
      user,
      // abortTimeout,
    } as WebAuthnRegistrationObject;
  
  // This is authentication
  } else {
    return {
      userVerification,
      hints,
      extensions: { txAuthSimple },
      customTimeout,
      // abortTimeout,
    } as WebAuthnAuthenticationObject
  }
}

const collectCredentials = () => {
  const cards = document.querySelectorAll<HTMLDivElement>('#credentials .mdc-card__primary-action');

  const credentials: PublicKeyCredentialDescriptorJSON[] = [];

  // Traverse all checked credentials
  cards.forEach(card => {
    const checkbox = card.querySelector<Checkbox>('mwc-checkbox.credential-checkbox');
    if (checkbox?.checked) {
      // Look for all checked transport checkboxes
      const _transports = card.querySelectorAll<Checkbox>('mwc-checkbox.transport-checkbox[checked]');
      // Convert checkboxes into a list of transports
      const transports = Array.from(_transports).map(_transport => {
        const iconNode = <IconButton>_transport.previousElementSibling;
        const index = Object.values(transportIconMap).findIndex(_transport => _transport == iconNode.icon);
        return <AuthenticatorTransport>Object.keys(transportIconMap)[index];
      });
      credentials.push({
        id: card.id.substring(3), // Remove first `ID-`
        type: 'public-key',
        transports
      });
    }
  });

  return credentials;
};

/**
 *  Ripple on the specified credential card to indicate it's found.
 * @param credID 
 */
const rippleCard = (credID: string) => {
  const ripple = new MDCRipple($(`#${credID}`));
  ripple.activate();
  ripple.deactivate();
}

async function parseRegistrationCredential(
  cred: RegistrationCredential
): Promise<any> {
  const credJSON = {
    id: cred.id,
    rawId: cred.id,
    type: cred.type,
    response: {
      clientDataJSON: {},
      attestationObject: {
        fmt: 'none',
        attStmt: {},
        authData: {},
      },
      transports: <any>[],
    },
    clientExtensionResults: {},
  };

  const decoder = new TextDecoder('utf-8');
  credJSON.response.clientDataJSON = JSON.parse(decoder.decode(cred.response.clientDataJSON));
  const attestationObject = cbor.decodeAllSync(cred.response.attestationObject)[0]

  attestationObject.authData = await parseAuthData(attestationObject.authData);
  credJSON.response.attestationObject = attestationObject;

  if (cred.response.getTransports) {
    credJSON.response.transports = cred.response.getTransports();
  }

  credJSON.clientExtensionResults = parseClientExtensionResults(cred);

  return credJSON;
};

async function parseAuthenticationCredential(
  cred: AuthenticationCredential
): Promise<any> {
  const userHandle = cred.response.userHandle ? base64url.encode(cred.response.userHandle) : undefined;

  const credJSON = {
    id: cred.id,
    rawId: cred.id,
    type: cred.type,
    response: {
      clientDataJSON: {},
      authenticatorData: {},
      signature: base64url.encode(cred.response.signature),
      userHandle,
    },
    clientExtensionResults: {},
  };

  const decoder = new TextDecoder('utf-8');
  credJSON.response.clientDataJSON = JSON.parse(decoder.decode(cred.response.clientDataJSON));
  credJSON.response.authenticatorData = await parseAuthenticatorData(new Uint8Array(cred.response.authenticatorData));

  credJSON.clientExtensionResults = parseClientExtensionResults(cred);

  return credJSON;
}

async function parseAuthData(
  buffer: any
): Promise<any> {
  const authData = {
    rpIdHash: '',
    flags: {
      up: false,
      uv: false,
      be: false,
      bs: false,
      at: false,
      ed: false,
    },
    counter: 0,
    aaguid: '',
    credentialID: '',
    credentialPublicKey: '',
    extensions: {}
  };

  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  authData.rpIdHash = [...rpIdHash].map(x => x.toString(16).padStart(2, '0')).join('');

  const flags = (buffer.slice(0, 1))[0];
  buffer = buffer.slice(1);
  authData.flags = {
    up: !!(flags & (1 << 0)),
    uv: !!(flags & (1 << 2)),
    be: !!(flags & (1 << 3)),
    bs: !!(flags & (1 << 4)),
    at: !!(flags & (1 << 6)),
    ed: !!(flags & (1 << 7)),
  };

  const counter = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  authData.counter = counter.readUInt32BE(0);

  if (authData.flags.at) {
    // Decode AAGUID
    let AAGUID = buffer.slice(0, 16);
    AAGUID = Array.from(AAGUID).map(a => (<Number>a).toString(16).padStart(2, '0'));
    authData.aaguid = `${AAGUID.splice(0,4).join('')}-${AAGUID.splice(0,2).join('')}-${AAGUID.splice(0,2).join('')}-${AAGUID.splice(0).join('')}`;
    buffer = buffer.slice(16);

    const credIDLenBuf = buffer.slice(0, 2);
    buffer = buffer.slice(2);
    const credIDLen = credIDLenBuf.readUInt16BE(0)
    // Decode Credential ID
    authData.credentialID = base64url.encode(buffer.slice(0, credIDLen));
    buffer = buffer.slice(credIDLen);

    const decodedResults = cbor.decodeAllSync(buffer.slice(0));
    // Decode the public key
    if (decodedResults[0]) {
      authData.credentialPublicKey = base64url.encode(Uint8Array.from(cbor.encode(decodedResults[0])).buffer);
    }
    // Decode extensions
    if (decodedResults[1]) {
      authData.extensions = decodedResults[1];
    }
  }

  return authData;
}

async function parseAuthenticatorData(
  buffer: any
): Promise<any> {
  const authData = {
    rpIdHash: '',
    flags: {
      up: false,
      uv: false,
      be: false,
      bs: false,
      at: false,
      ed: false,
    },
  };

  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  authData.rpIdHash = [...rpIdHash].map(x => x.toString(16).padStart(2, '0')).join('');

  const flags = (buffer.slice(0, 1))[0];
  buffer = buffer.slice(1);
  authData.flags = {
    up: !!(flags & (1 << 0)),
    uv: !!(flags & (1 << 2)),
    be: !!(flags & (1 << 3)),
    bs: !!(flags & (1 << 4)),
    at: !!(flags & (1 << 6)),
    ed: !!(flags & (1 << 7)),
  };

  return authData;
}

function parseClientExtensionResults(
  credential: RegistrationCredential | AuthenticationCredential
): AuthenticationExtensionsClientOutputs {
  const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};
  if (credential.getClientExtensionResults) {
    const extensions: AuthenticationExtensionsClientOutputs = credential.getClientExtensionResults();
    if (extensions.credProps) {
      clientExtensionResults.credProps = extensions.credProps;
    }
  }
  return clientExtensionResults;
}

/**
 * Fetch and render the list of credentials.
 */
const listCredentials = async (): Promise<void> => {
  loading.start();
  try {
    const credentials = <StoredCredential[]>await _fetch('/webauthn/getCredentials');
    loading.stop();
    render(credentials.map(cred => {
      const extensions = cred.clientExtensionResults;
      const transports = cred.transports as string[];
      const aaguid = cred.aaguid || '00000000-0000-0000-0000-000000000000';
      const authenticatorType = `${cred.user_verifying?'User Verifying ':''}`+
        `${cred.authenticatorAttachment==='platform'?'Platform ':
           cred.authenticatorAttachment==='cross-platform'?'Roaming ':''}Authenticator`;
      return html`
      <div class="mdc-card">
        <div class="mdc-card__primary-action" id="ID-${cred.credentialID}">
          <div class="card-title mdc-card__action-buttons">
            <div class="cred-title mdc-card__action-button">
              <mwc-formfield label="${cred.browser}/${cred.os}/${cred.platform}">
                <mwc-checkbox class="credential-checkbox" title="Check to exclude or allow this credential" checked></mwc-checkbox>
                ${(aaguids as AAGUIDs)[aaguid] ? html`
                <mwc-icon-button title="${(aaguids as AAGUIDs)[aaguid]?.name}">
                  <img src="${(aaguids as AAGUIDs)[aaguid].icon_light}">
                </mwc-icon-button>`:''}
              </mwc-formfield>
            </div>
            <div class="mdc-card__action-icons">
              <mwc-icon-button @click="${removeCredential(cred.credentialID)}" icon="delete_forever" title="Removes this credential registration from the server"></mwc-icon>
            </div>
          </div>
          <div class="card-body">
            <dt>Authenticator Type</dt>
            <dd>${authenticatorType}</dd>
            <dt>Credential Type</dt>
            <dd>${cred.credentialBackedUp ? 'Multi device' : 'Single device'}</dd>
            <dt>AAGUID</dt>
            <dd>${aaguid}</dd>
            <dt>Transports</dt>
            <dd class="transports">
              ${!transports.length ? html`
              <span>N/A</span>
              ` : transports.map(transport => html`
              <mwc-formfield>
                <mwc-icon-button icon="${transportIconMap[transport]}" title="${transport}"></mwc-icon-button>
                <mwc-checkbox class="transport-checkbox" title="Check to request '${transport}' as a transport on authentication." checked></mwc-checkbox>
              </mwc-formfield>
              `)}
            </dd>
            ${cred.registered ? html`
            <dt>Enrolled at</dt>
            <dd>${(new Date(cred.registered)).toLocaleString()}</dd>`:''}
            ${extensions?.credProps ? html`
            <dt>Credential Properties Extension</dt>`:''}
            ${extensions.credProps?.rk ? html`
            <dd>Discoverable Credentials: ${extensions.credProps.rk?'true':'false'}</dd>`:''}
            ${extensions.credProps?.authenticatorDisplayName ? html`
            <dd>Authenticator display name: ${extensions.credProps.authenticatorDisplayName}</dd>`:''}
            <dt>Public Key</dt>
            <dd>${cred.credentialPublicKey}</dd>
            <dt>Credential ID</dt>
            <dd>${cred.credentialID}</dd>
            <div class="mdc-card__ripple"></div>
          </div>
        </div>
      </div>
    `}), $('#credentials'));
    loading.stop();
    if (!$('#exclude-all-credentials').checked) {
      const cards = document.querySelectorAll<HTMLDivElement>('#credentials .mdc-card__primary-action');
      cards.forEach(card => {
        const checkbox = card.querySelector<Checkbox>('mwc-checkbox');
        if (checkbox) checkbox.checked = false;
      });
    }
  } catch (e) {
    console.error(e);
    showSnackbar('Loading credentials failed.');
    loading.stop();
  }
};

/**
 *  Register a new credential.
 * @param opts 
 */
const registerCredential = async (opts: WebAuthnRegistrationObject): Promise<any> => {
  // Fetch credential creation options from the server.
  /*Credential options are parameters passed to navigator.credentials.create()
   defining the relying party, user details, security challenge,
   allowed authenticator types, and existing credentials to prevent duplicates.
  These options are fetched from the server, decoded from base64url,
   and then passed to the browser to initiate WebAuthn registration.*/
  const options: PublicKeyCredentialCreationOptionsJSON =
      await _fetch('/webauthn/registerRequest', opts);

  // Decode encoded parameters.
  const user = {  // Convert user object by decoding the base64url user ID
    ...options.user,
    id: base64url.decode(options.user.id)
  } as PublicKeyCredentialUserEntity;
  const challenge = base64url.decode(options.challenge);  // Decode the challenge from base64url
  const _excludeCredentials: PublicKeyCredentialDescriptorJSON[] = collectCredentials();  // Get existing credentials to avoid duplicate registration
  const excludeCredentials = _excludeCredentials.map(cred => {  // Decode each excluded credential's ID
    return {
      ...cred,
      id: base64url.decode(cred.id),
    } as PublicKeyCredentialDescriptor;
  });
  const decodedOptions = {  // Assemble complete, decoded options for credential creation
    ...options,
    user,
    challenge,
    hints: opts.hints,
    excludeCredentials,
  } as PublicKeyCredentialCreationOptions;

  console.log('[CredentialCreationOptions]', decodedOptions);  // Log options for debugging

  // Create a new attestation.
  const credential = await navigator.credentials.create({  // Request browser to create new WebAuthn credential
    publicKey: decodedOptions
  }) as RegistrationCredential;

  // Encode the attestation.
  const rawId = base64url.encode(credential.rawId);  // Encode credential's raw ID back to base64url
  const clientDataJSON = base64url.encode(credential.response.clientDataJSON);  // Encode client data
  const attestationObject = base64url.encode(credential.response.attestationObject);  // Encode attestation object
  const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};  // Initialize container for extension results

  // if `getClientExtensionResults()` is supported, serialize the result.
  if (credential.getClientExtensionResults) {  // Check if browser supports extension results
    const extensions: AuthenticationExtensionsClientOutputs = credential.getClientExtensionResults();  // Get extension results
    if (extensions.credProps) {  // If credential properties extension exists
      clientExtensionResults.credProps = extensions.credProps;  // Copy credential properties
    }
  }
  let transports: any[] = [];  // Initialize transports array

  // if `getTransports()` is supported, serialize the result.
  if (credential.response.getTransports) {  // Check if authenticator provides transport info
    transports = credential.response.getTransports();  // Get supported transport methods (USB, NFC, BLE, etc)
  }

  const encodedCredential = {  // Build encoded credential response object for server
    id: credential.id,
    rawId,
    response: {
      clientDataJSON,
      attestationObject,
      transports,
    },
    type: credential.type,
    clientExtensionResults,
  } as RegistrationResponseJSON;

  const parsedCredential = await parseRegistrationCredential(credential);  // Parse credential into readable format

  console.log('[RegistrationResponseJSON]', parsedCredential);  // Log parsed credential for debugging

  // Verify and store the attestation.
  await _fetch('/webauthn/registerResponse', encodedCredential);  // Send encoded credential to server for verification

  return parsedCredential;  // Return parsed credential to caller
};

/**
 *  Authenticate the user with a credential.
 * @param opts 
 * @returns 
 */
// Define an async function that authenticates a user using WebAuthn
// Takes WebAuthnAuthenticationObject options and returns a Promise of any type
const authenticate = async (opts: WebAuthnAuthenticationObject): Promise<any> => {

  // STEP 1: FETCH AUTHENTICATION OPTIONS FROM SERVER
  // Fetch the credential request options from the server endpoint
  // This tells the browser what kind of authentication is expected
  const options: PublicKeyCredentialRequestOptionsJSON =
      await _fetch('/webauthn/authRequest', opts);

  // STEP 2: DECODE THE CHALLENGE
  // WebAuthn uses a random challenge to prevent replay attacks
  // The challenge comes base64url-encoded, so decode it back to binary
  const challenge = base64url.decode(options.challenge);

  // STEP 3: PROCESS ALLOWED CREDENTIALS
  // Get the list of allowed credentials from a helper function or empty array
  // $('#empty-allow-credentials') checks if a checkbox is checked to allow any credential
  const _allowCredentials: PublicKeyCredentialDescriptorJSON[] =
      $('#empty-allow-credentials').checked ? [] : collectCredentials();

  // Transform each credential: decode the base64url-encoded ID back to binary
  // This creates the actual PublicKeyCredentialDescriptor objects the browser needs
  const allowCredentials = _allowCredentials.map(cred => {
    return {
      ...cred,                    // Keep all original properties
      id: base64url.decode(cred.id),  // Decode the credential ID from base64url
    } as PublicKeyCredentialDescriptor;
  });

  // STEP 4: BUILD COMPLETE OPTIONS OBJECT
  // Combine all the authentication options into the final request object
  const decodedOptions = {
    ...options,           // Include all original options
    allowCredentials,     // Add the processed allowed credentials
    hints: opts.hints,    // Add any authentication hints (e.g., "security-key", "client-device")
    challenge,            // Add the decoded binary challenge
  } as PublicKeyCredentialRequestOptions;

  // Log the request options for debugging purposes
  console.log('[CredentialRequestOptions]', decodedOptions);

  // STEP 5: PERFORM THE AUTHENTICATION
  // Ask the browser to authenticate the user using WebAuthn
  // This will trigger the browser's native UI (fingerprint, security key, etc.)
  const credential = await navigator.credentials.get({
    publicKey: decodedOptions
  }) as AuthenticationCredential;

  // STEP 6: ENCODE CREDENTIAL RESPONSE FOR SERVER
  // The browser returns binary data, but we need to send it as base64url to the server
  const rawId = base64url.encode(credential.rawId);           // Encode the credential ID
  const authenticatorData = base64url.encode(credential.response.authenticatorData);  // Encode authenticator data
  const clientDataJSON = base64url.encode(credential.response.clientDataJSON);        // Encode client data
  const signature = base64url.encode(credential.response.signature);                  // Encode the cryptographic signature
  const userHandle = credential.response.userHandle ?        // User handle is optional
      base64url.encode(credential.response.userHandle) : undefined;

  // STEP 7: HANDLE CLIENT EXTENSIONS
  // Initialize empty object for any WebAuthn extension results
  const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};

  // Check if the browser supports the getClientExtensionResults method
  // This method returns additional data from WebAuthn extensions
  if (credential.getClientExtensionResults) {
    const extensions: AuthenticationExtensionsClientOutputs = credential.getClientExtensionResults();
    // If credential properties extension is present, include it in results
    if (extensions.credProps) {
      clientExtensionResults.credProps = extensions.credProps;
    }
  }

  // STEP 8: BUILD ENCODED CREDENTIAL OBJECT
  // Create the final JSON-serializable object to send to the server
  const encodedCredential = {
    id: credential.id,                    // The credential ID as a string
    rawId,                                // Base64url-encoded raw ID
    response: {
      authenticatorData,                  // Base64url-encoded authenticator data
      clientDataJSON,                    // Base64url-encoded client data
      signature,                         // Base64url-encoded signature
      userHandle,                        // Base64url-encoded user handle (if present)
    },
    type: credential.type,               // Usually "public-key"
    clientExtensionResults,              // Any extension results
  } as AuthenticationResponseJSON;

  // STEP 9: PARSE FOR CLIENT DISPLAY
  // Convert the credential to a more user-friendly format (likely for UI display)
  const parsedCredential = await parseAuthenticationCredential(credential);

  // Log the parsed credential for debugging
  console.log('[AuthenticationResponseJSON]', parsedCredential);

  // STEP 10: VERIFY AND STORE ON SERVER
  // Send the encoded credential to the server for verification
  // The server will validate the signature against the stored public key
  await _fetch('/webauthn/authResponse', encodedCredential);

  // STEP 11: RETURN THE PARSED CREDENTIAL
  // Return the user-friendly credential object (likely for UI feedback)
  return parsedCredential;
};

/**
 *  Remove a credential.
 * @param credId 
 * @returns 
 */
const removeCredential = (credId: string) => async () => {
  if (!confirm('Are you sure you want to remove this credential?')) {
    return;
  }
  try {
    loading.start();
    await _fetch('/webauthn/removeCredential', { credId });
    showSnackbar('The credential has been removed.');
    listCredentials();
  } catch (e) {
    console.error(e);
    showSnackbar('Removing the credential failed.');
  }
};

const onExcludeAllCredentials = (e: any): void => {
  const checked = !e.target.checked;
  const cards = document.querySelectorAll<HTMLDivElement>('#credentials .mdc-card__primary-action');
  cards.forEach(card => {
    const checkbox = card.querySelector<Checkbox>('mwc-checkbox');
    if (checkbox) checkbox.checked = checked;
  });
  e.target.checked = checked;
}

/**
 * When the user icon is clicked, show the User Info dialog.
 */
const onUserIconClicked = () => {
  const _userInfo = localStorage.getItem('userInfo');
  if (_userInfo) {
    const userInfo = JSON.parse(_userInfo);
    $('#username').value = userInfo.name;
    $('#display-name').value = userInfo.displayName;
    $('#picture-url').value = userInfo.picture;
  }
  $('#user-info').show();
}

/**
 * When "Save" button in the User Info dialog is clicked, update the user info.
 * @param e 
 */
const onUserInfoUpdate = (e: any): void => {
  const username = $('#username');
  const displayName = $('#display-name');
  const pictureUrl = $('#picture-url');

  let success = true;
  if (!username.checkValidity()) {
    username.reportValidity();
    success = false;
  }
  if (!displayName.checkValidity()) {
    displayName.reportValidity();
    success = false;
  }
  if(!pictureUrl.checkValidity()) {
    pictureUrl.reportValidity();
    success = false;
  }

  if (!success) {
    e.stopPropagation();
  } else {
    localStorage.setItem('userInfo', JSON.stringify({
      name: username.value,
      displayName: displayName.value,
      picture: pictureUrl.value,
    }));
  }
};

/**
 * Determine whether
 * `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
 * function is available.
 */
const onISUVPAA = async (): Promise<void> => {
  if (window.PublicKeyCredential) {
    if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
      const result = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (result) {
        showSnackbar('User Verifying Platform Authenticator is *available*.');
      } else {
        showSnackbar('User Verifying Platform Authenticator is not available.');
      }
    } else {
      showSnackbar('IUVPAA function is not available.');
    }
  } else {
    showSnackbar('PublicKeyCredential is not availlable.');
  }
}

/**
 * On "Register New Credential" button click, invoke `registerCredential()`
 * function to register a new credential with advanced options.
 */
const onRegisterNewCredential = async (): Promise<void> => {
  loading.start();
  const opts = <WebAuthnRegistrationObject>collectOptions('registration');
  try {
    const parsedCredential = await registerCredential(opts);
    showSnackbar('A credential successfully registered!', parsedCredential);
    listCredentials();
  } catch (e: any) {
    console.error(e);
    showSnackbar(e.message);
  } finally {
    loading.stop();
  }
};

/**
 * On "Register Platform Authenticator" button click, invoke
 * `registerCredential()` function to register a new credential with advanced
 * options overridden by `authenticatorAttachment == 'platform'` and
 * `userVerification = 'required'`.
 */
const onRegisterPlatformAuthenticator = async (): Promise<void> => {
  loading.start();
  const opts = <WebAuthnRegistrationObject>collectOptions('registration');
  opts.authenticatorSelection = opts.authenticatorSelection || {};
  opts.authenticatorSelection.authenticatorAttachment = 'platform';
  try {
    const parsedCredential = await registerCredential(opts);
    showSnackbar('A credential successfully registered!', parsedCredential);
    listCredentials();
  } catch (e: any) {
    console.error(e);
    showSnackbar(e.message);
  } finally {
    loading.stop();
  }
};

/**
 * On "Authenticate" button click, invoke `authenticate()` function to
 * authenticate the user.
 */
const onAuthenticate = async (): Promise<void> => {
  loading.start();
  const opts = <WebAuthnAuthenticationObject>collectOptions('authentication');
  try {
    const parsedCredential = await authenticate(opts);
    // Prepended `ID-` is necessary to avoid IDs start with a number.
    rippleCard(`ID-${parsedCredential.id}`);
    showSnackbar('Authentication succeeded!', parsedCredential);
    listCredentials();
    window.location.href = '/protected';
  } catch (e: any) {
    console.error(e);
    showSnackbar(e.message);
  } finally {
    loading.stop();
  }
};

const onTxAuthSimpleSiwtch = async (): Promise<void> => {
  $('#tx-auth-simple').disabled = $('#switch-tx-auth-simple').checked;
}

loading.start();

$('#isuvpaa-button').addEventListener('click', onISUVPAA);
$('#credential-button').addEventListener('click', onRegisterNewCredential);
$('#platform-button').addEventListener('click', onRegisterPlatformAuthenticator);
$('#authenticate-button').addEventListener('click', onAuthenticate);
$('#exclude-all-credentials').addEventListener('click', onExcludeAllCredentials);
$('#user-icon').addEventListener('click', onUserIconClicked);
$('#signout').addEventListener('click', onSignout);
$('#save-user-info').addEventListener('click', onUserInfoUpdate);
$('#switch-tx-auth-simple').addEventListener('click', onTxAuthSimpleSiwtch);