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

    serializePublicKeyCredential(cred: PublicKeyCredential): any {
    const attResp = cred.response as AuthenticatorAttestationResponse;

    return {
      id: cred.id,
      type: cred.type,
      rawId: this.bufferToBase64Url(cred.rawId),
      response: {
        clientDataJSON: this.bufferToBase64Url(attResp.clientDataJSON),
        attestationObject: this.bufferToBase64Url(attResp.attestationObject),
      }
    };
  }

  bufferToBase64Url(buf: ArrayBuffer): string {
    const binary = String.fromCharCode(...new Uint8Array(buf));
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
    if (!credential) throw new Error('Credential creation failed');

    // Serialize and send
    const serialized = this.serializePublicKeyCredential(credential);

    await firstValueFrom(
      this.http.post('/api/register/complete', serialized, {
        headers: { 'x-username': username }
      })
    );
  }

  async authenticate(username: string) {
    const options = await firstValueFrom(this.http.post('/api/auth/begin', { username }));
    const assertion = await navigator.credentials.get({
      publicKey: options as PublicKeyCredentialRequestOptions
    });
    const result = await firstValueFrom(this.http.post('/api/auth/complete', assertion, {
      headers: { 'x-username': username },
      responseType: 'json'
    }));
    return result;
  }
  

}
