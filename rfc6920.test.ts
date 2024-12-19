import { test, describe } from "node:test"
import assert from "node:assert"
import { example_8_1_withAuthority, example_8_1_withAuthorityHttp, example_8_1_withoutAuthority, example_8_2, INamedInformationURI } from "./rfc6920.js"
import RFC6920 from "./rfc6920.js"

await describe(`naming-things-with-hashes`, async (s) => {
  await test(
    `8.1.  Hello World!`,
    async t => {
      const examples = {
        example_8_1_withAuthority,
        example_8_1_withAuthorityHttp,
        example_8_1_withoutAuthority,
      }
      for (const [name, uri] of Object.entries(examples)) {
        await t.test(`${uri}`, async t => {
          const url = new URL(uri)
          switch (url.protocol) {
            case "ni:": {
              const ni = RFC6920.parse(url.toString())
              await testNiURI(ni, {
                expectations: {
                  algorithm: 'sha-256',
                  formattedHash: 'f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk',
                }
              })
              break;
            }
            case "http:":
            case "https:": {
              break;
            }
            default:
              throw new Error(`unexpected protocol ${url.protocol}`, {
                cause: {
                  url,
                  name,
                }
              })
          }
        })
      }
    }
  )

  await test(
    `8.2.  Public Key Examples`,
    async t => {
      const examples = {
        example_8_2
      }
      for (const [name, uri] of Object.entries(examples)) {
        await t.test(`${uri}`, async t => {
          const url = new URL(uri)
          switch (url.protocol) {
            case "ni:": {
              const ni = RFC6920.parse(url.toString())
              await testNiURI(ni, {
                expectations: {
                  algorithm: 'sha-256',
                  formattedHash: 'UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q',
                }
              })
              break;
            }
            default:
              throw new Error(`unexpected protocol ${url.protocol}`, {
                cause: {
                  url,
                  name,
                }
              })
          }
        })
      }
    }
  )
})

async function testNiURI(ni: INamedInformationURI, options: {
  expectations: {
    algorithm: string
    formattedHash: string
  }
}) {
  assert.ok(ni.algorithm)
  if (options.expectations.algorithm) {
    assert.equal(ni.algorithm, options.expectations.algorithm)
  }
  if (options.expectations.formattedHash) {
    assert.equal(ni.formattedHash, options.expectations.formattedHash)
  }
  // assert.ok(ni.authority)
  // assert.ok(ni.digestAlgorithm)
  // assert.ok(ni.digestValue)
  // ni.queryParameters
}
