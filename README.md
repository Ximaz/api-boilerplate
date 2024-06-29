# API Boilerplate

An expressJS template which uses TypeScript to build a REST API easily with
security concernes builtin.

# Stack

This project uses the following stack :

- Backend Language : `TypeScript`,
- Backend Library : `ExpressJS`,
- Database : `PostgreSQL`,
- Authentication : `jsonwebtoken` for JWT authentication and `jose` for JWT encryption & decryption,
- Password Hashing : `Argon2id` [according to OWASP security advice](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id),

# Communications

All communitcation will be in a JSON format.
