declare module 'cbor-web' {
  export function encode(input: any): Uint8Array;
  export function decodeFirst(input: ArrayBuffer | Uint8Array): Promise<any>;
}