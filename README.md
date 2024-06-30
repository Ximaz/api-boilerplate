# API Boilerplate

An expressJS template which uses TypeScript to build a REST API easily with
security concernes builtin.

# Stack

This project uses the following stack :

- Backend Language : `TypeScript`,
- Backend Library : `ExpressJS`,
- Authentication : `jsonwebtoken` for JWT signature and verification, `jose`
for JWT encryption & decryption, and `pem-jwk` to convert `JWK` public and
private keys to PEM format and vice-versa. The JWT is retrieved from the
`Authorization` HTTP header as a `Bearer` token.
- Password Hashing : `Argon2id` [according to OWASP security advice](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id),

# Communications

All communitcation will be in a JSON format.

# Controllers

### `auth`

This controller generates a new JWE and sends it to the client, with no
credential check. Your job will be to implement some.

### `user`

This is a fake controller to showcase how to use the auth middleware.
