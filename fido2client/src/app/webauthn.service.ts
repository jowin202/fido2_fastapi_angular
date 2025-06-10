// src/app/webauthn.service.ts
import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import * as cbor from 'cbor';
import { decodeFirst, encode } from 'cbor-web';

@Injectable({
  providedIn: 'root'
})
export class WebauthnService {

  constructor(private http: HttpClient) {}

  
  private toUint8Array(input: unknown): Uint8Array {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer);

    // Handle base64url string (common case)
    if (typeof input === 'string') {
      const padding = '='.repeat((4 - (input.length % 4)) % 4);
      const base64 = input.replace(/-/g, '+').replace(/_/g, '/') + padding;
      const raw = atob(base64);
      return new Uint8Array([...raw].map(char => char.charCodeAt(0)));
    }

    throw new TypeError('Expected BufferSource or base64url string');
  }

  toBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }




  async register(username: string): Promise<void> {
    // Step 1: Begin registration
    const responseBlob = await firstValueFrom(
      this.http.post('/api/register/begin', { username }, { responseType: 'blob' })
    );

    // Step 2: Decode CBOR response
    const arrayBuffer = await responseBlob.arrayBuffer();
    const decoded = await decodeFirst(arrayBuffer) as { publicKey: PublicKeyCredentialCreationOptions };
    const publicKey = decoded.publicKey;

    // Step 3: Normalize fields
    publicKey.challenge = this.toUint8Array(publicKey.challenge);
    publicKey.user.id = this.toUint8Array(publicKey.user.id);

    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
        ...cred,
        id: this.toUint8Array(cred.id),
      }));
    }

    // Step 4: Call WebAuthn API
    const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential;

    // Narrow response type
    const attestationResponse = credential.response as AuthenticatorAttestationResponse;

    const credentialData = {
      id: credential.id,
      rawId: this.toBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: this.toBase64Url(attestationResponse.clientDataJSON),
        attestationObject: this.toBase64Url(attestationResponse.attestationObject),
      },
    };

    await firstValueFrom(this.http.post('/api/register/complete', {
      username,
      credential: credentialData,
    }));

    console.log('Registration complete');
}



















  async authenticate(username: string): Promise<any> {
    // Step 1: Request CBOR-encoded challenge
    const responseBuffer = await firstValueFrom(
      this.http.post('/api/auth/begin', { username }, { responseType: 'arraybuffer' })
    );

    // Step 2: Decode CBOR
    const decoded = await decodeFirst(responseBuffer) as { publicKey: any };
    const publicKey = decoded.publicKey as PublicKeyCredentialRequestOptions;

    // Step 3: Convert necessary fields to ArrayBuffer
    publicKey.challenge = this.bufferFrom(publicKey.challenge);
    if (Array.isArray(publicKey.allowCredentials)) {
      publicKey.allowCredentials = publicKey.allowCredentials.map((cred: any) => ({
        ...cred,
        id: this.bufferFrom(cred.id),
      }));
    }

    // Step 4: Call WebAuthn API
    const credential = await navigator.credentials.get({ publicKey }) as PublicKeyCredential;

    // Step 5: Send result to backend for verification
    const resultData = this.credentialToJSON(credential);

    const result = await firstValueFrom(
      this.http.post('/api/auth/complete', resultData, {
        headers: { 'x-username': username },
        responseType: 'json',
      })
    );

    return result;
  }

  // Utility: Converts various formats to ArrayBuffer
private bufferFrom(buf: unknown): ArrayBuffer {
  if (buf instanceof ArrayBuffer) {
    return buf;
  }

  if (buf instanceof Uint8Array) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  // From CBOR decoder: [number, number, ...]
  if (Array.isArray(buf) && buf.every((v) => typeof v === 'number')) {
    return new Uint8Array(buf).buffer;
  }

  // From CBOR or backend: base64url-encoded string
  if (typeof buf === 'string') {
    const base64 = buf.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  throw new Error(`Unsupported buffer type: ${typeof buf}`);
}


  // Utility: Encode ArrayBuffer to base64url string
  private bufferEncode(value: ArrayBuffer): string {
    const uint8Array = new Uint8Array(value);
    let str = '';
    for (const byte of uint8Array) {
      str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Utility: Convert WebAuthn response to JSON-safe format
  private credentialToJSON(cred: PublicKeyCredential): any {
    const response = cred.response as AuthenticatorAssertionResponse;

    return {
      id: cred.id,
      type: cred.type,
      rawId: this.bufferEncode(cred.rawId),
      response: {
        authenticatorData: this.bufferEncode(response.authenticatorData),
        clientDataJSON: this.bufferEncode(response.clientDataJSON),
        signature: this.bufferEncode(response.signature),
        userHandle: response.userHandle ? this.bufferEncode(response.userHandle) : null,
      },
    };
  }



  

}
