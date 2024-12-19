# naming-things-with-hashes

TypeScript modules for [RFC 6920 Naming Things with Hashes](https://www.rfc-editor.org/rfc/rfc6920).

## Usage

```js
import RFC6920 from "naming-things-with-hashes/rfc6920"

// https://www.rfc-editor.org/rfc/rfc6920#section-8.2
const example_8_2 = 'ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q'

const ni = RFC6920.parse(example_8_2)
```
