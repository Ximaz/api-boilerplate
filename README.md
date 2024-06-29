# API Boilerplate

An expressJS template which uses TypeScript to build a REST API easily with
security concernes builtin.

# Stack

This project uses the following stack :

- Backend Language : `TypeScript`,
- Backend Library : `ExpressJS`,
- Database : `PostgreSQL`,
- Authentication : `jsonwebtoken` for JWT signature and verification, `jose`
for JWT encryption & decryption, and `pem-jwk` to convert `JWK` public and
private keys to PEM format and vice-versa.
- Password Hashing : `Argon2id` [according to OWASP security advice](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id),

# Communications

All communitcation will be in a JSON format.
