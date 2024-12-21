// https://www.rfc-editor.org/rfc/rfc6920#section-8.1
export const example_8_1_withoutAuthority = 'ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk' as const
export const example_8_1_withAuthority = 'ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk' as const
export const example_8_1_withAuthorityHttp = 'http://example.com/.well-known/ni/sha-256/f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk' as const
export const example_8_2 = 'ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q' as const

export type HashAlgorithm = Parameters<typeof globalThis.crypto.subtle.digest>[0]
export type MimeType = `${string}/${string}`

export const NI_URL_PATTERN = /^ni:\/\/(?<authority>[^/]+)?\/(?<algorithm>[^/;]+);(?<hashb64url>[^?]+)(?<querystring>\?.+)?/

export interface INamedInformationURI<
  Algorithm extends HashAlgorithm = HashAlgorithm,
  ContentType extends Nullable<MimeType> = null | MimeType,
> {
  readonly algorithm: Algorithm
  readonly hash: ArrayBuffer
  readonly contentType: ContentType
  readonly formattedHash: string
  readonly formattedAlgorithm: string
  readonly query: string | undefined
  toString(): NiUriString  
}

type Nullable<T> = T | null;

/**
 * a 'ni:…' URI as defined in RFC 6920: Naming Things with Hashes
 */
class NamedInformationURI<
  Algorithm extends HashAlgorithm = HashAlgorithm,
  ContentType extends MimeType | null = null|MimeType,
> implements INamedInformationURI<Algorithm> {
  readonly algorithm: Algorithm
  readonly hash: ArrayBuffer
  readonly contentType: ContentType
  readonly formattedHash: string
  readonly formattedAlgorithm: string
  readonly query: string | undefined = undefined
  constructor(options: {
    algorithm: Algorithm,
    hash: ArrayBuffer,
    contentType: ContentType,
  }) {
    this.algorithm = options.algorithm
    this.hash = options.hash
    this.contentType = options.contentType
    this.formattedHash = base64urlEncode(this.hash)
    this.formattedAlgorithm = String(this.algorithm).toLowerCase()
    // build and set this.query
    {
      const searchParams = new URLSearchParams
      if (options.contentType) {
        searchParams.set('ct', options.contentType)
      }
      this.query = searchParams.toString()
    }
  }
  toString() {
    const ni: NiUriString = `ni:///${this.formattedAlgorithm};${this.formattedHash}${this.query ? '?' : ''}${this.query}`
    return ni
  }
}

export function create
<
  Algorithm extends HashAlgorithm,
  ContentType extends MimeType | null,
>
(options: {
  algorithm: Algorithm,
  hash: ArrayBuffer,
  contentType: ContentType,
}): INamedInformationURI<Algorithm> {
  return new NamedInformationURI(options)
}

/**
 * construct a NamedInformationURI object from input data.
 * hashing is async.
 */
export async function fromData
<
  Algorithm extends HashAlgorithm,
  ContentType extends Nullable<MimeType>,
>
(options: {
  algorithm: Algorithm,
  data: ArrayBuffer|DataView|Uint8Array,
  contentType: ContentType,
  subtleCrypto?: Pick<typeof globalThis.crypto.subtle, 'digest'>
}): Promise<NamedInformationURI<Algorithm, ContentType>> {
  const subtleCrypto = options.subtleCrypto || globalThis.crypto.subtle
  if ( ! subtleCrypto) throw new Error(`unable to find WebCrypto subtle api`)
  const hash = await subtleCrypto.digest(options.algorithm, options.data)
  return new NamedInformationURI({
    ...options,
    hash,
  })
}

export async function fromBlob
<
  Algorithm extends HashAlgorithm,
>
(options: {
  algorithm: Algorithm,
  blob: Blob,
  subtleCrypto?: Pick<typeof globalThis.crypto.subtle, 'digest'>
}) {
  return fromData({
    algorithm: options.algorithm,
    data: await options.blob.arrayBuffer(),
    contentType: (options.blob.type as MimeType) || null,
  })
}

/**
 * serialize a file path segment for the NamedInformationURI.
 * i.e. strip off 'ni:///'
 * @param {boolean} options.contentType - whether to include the ?ct= query param
 */
export function filePathSegment(ni: INamedInformationURI, options: { contentType: boolean }): string {
  return `${ni.formattedAlgorithm};${ni.formattedHash}${options.contentType ? `${ni.query ? '?' : ''}${ni.query}` : ''}`
}

export function decodeFilePathSegment(segment: string): INamedInformationURI {
  const match = segment.match(/([^/;]+);([^?]+)(\?.+)?/)
  if ( ! match) throw new Error(`unable to decode NamedInformationURI from string`)
  const [_, algorithm, hashBase64UrlEncoded, query] = match
  const searchParams = new URLSearchParams(query)
  const contentType = searchParams.get('ct')
  const hashB64 = base64urlToBase64(hashBase64UrlEncoded)
  const hash = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0))
  return new NamedInformationURI({
    hash: hash.buffer,
    algorithm,
    contentType: contentType as `${string}/${string}` | null,
  })
}

type NiAuthority = '' | string
type NiAlgorithm = string
type NiHashB64Url = string
type NiMediaType = string // dont be too strict
export type NiUriString<Alg extends NiAlgorithm=NiAlgorithm> = `ni://${NiAuthority}/${NiAlgorithm};${NiHashB64Url}${''|`?ct=${NiMediaType}`}`

export function isRFC6920Uri<Alg extends NiAlgorithm>(value: unknown): value is NiUriString<Alg> {
  if (typeof value !== 'string') return false
  const match = value.match(NI_URL_PATTERN)
  if ( ! match) return false
  return true;
}

export function parseRFC6920UriString(value: string) {
  const match = value.match(NI_URL_PATTERN)
  if ( ! match?.groups) {
    throw new Error('unable to parse string as RFC6920 URI', {
      cause: value
    })
  }
  const { authority, algorithm, hashb64url, querystring } = match.groups
  const searchParams = new URLSearchParams(querystring)
  const contentType = searchParams.get('ct')
  const hashB64 = base64urlToBase64(hashb64url)
  const hash = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0)).buffer
  return new NamedInformationURI({
    hash,
    algorithm,
    contentType: contentType as `${string}/${string}` | null,
  })
}

/**
 * tests a ni against some blob.
 * return true iff the ni is the hashname of the blob
 */
export async function test(hash: INamedInformationURI, data: Blob) {
  const dataNi = await fromBlob({
    algorithm: hash.algorithm,
    blob: data,
  })
  return hash.toString() === dataNi.toString()
}

const RFC6920 = {
  create,
  fromBlob,
  fromData,
  filePathSegment,
  is: isRFC6920Uri,
  parse: parseRFC6920UriString,
  test,
}

export default RFC6920

function base64urlEncode(data: ArrayBuffer) {
  const base64Encoded = btoa(String.fromCharCode(...new Uint8Array(data)));
  const base64urlEncoded = base64Encoded
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/g, '')
  return base64urlEncoded
}

function base64urlToBase64(base64UrlEncoded: string): string {
  const base64Encoded = base64UrlEncoded
  .replace(/-/g, '+')
  .replace(/_/g, '/');
  return base64Encoded
}

function base64ToBase64Url(base64Encoded: string): string {
  const base64UrlEncoded = base64Encoded
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/g, '')
  return base64UrlEncoded
}
