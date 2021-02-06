## crypto

 * [Java Security Developer's Gude](https://docs.oacle.com/en/java/javase/15/security/index.html)  
 * [JDK JavaDoc](https://docs.oracle.com/en/java/javase/15/docs/api/index.html)  
 * [Bouncy Castle Home Page](https://www.bouncycastle.org/java.html)  
 * [Bouncy Castle source code](https://github.com/bcgit/bc-java)  
 * [RFC 4880 - OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)  

### [Java Cryptography Tools and Techniques](https://leanpub.com/javacryptotoolsandtech)  

`OID` - object identifier  
`CSOR` - compurer security objects register  
`BER` - basic encoding rules  
`DER` - distinguished encoding rules  
`CER` - canonical encoding rules  
`TLV` - tag length value  
`OER` - octet encoding rules  
`BOER` - basic objects encoding rules  
`JCA` - java cryptography architecture   
`JSE` - java security extention  
`TLS` - transport layer security
`SSL` - secure socket layer  
`JSSE` - java security socket  
`SPI` - service provider interface  
`ECB` - Electronic Code Book  
`CBC` - Cipher Block Chaining
`IV` - Initialization vector

### Block and stream ciphers

#### Symmetric cipher 
 * Secret key to encrypt data.  
 * At least 112 bits of security   
 * `NIST`, `AES` - recommended cipher
   
#### Block Modes 
- `EBC` - Electornic Code Book. encrypt and decrypt data based on bits patterns in the book    
- `CBC` - Cipher Block Chaining. 
   - `IV` is used to initialise internal state and then XORing the state with each block of plane text    
   - `Padding` - add an extra block of padding  
   - `CTC` Cipher Text Stealing 
- `Streaming`- encrypt data of an arbitrary size without the use of padding.  
- `CTR` -   
- `CFB` Cipher FeedBack - 
- `OFB` Output FeedBack  

#### Stream Ciphers   
designedto generate only key-streams.  
Cipher based Input/Output  

### MessageDigest. Mac, HMAC, KDGF
Ways to verifying that data has not been tampered  

`Message Digests` are used to calculate a cryptographic checksum , or hash
for a paticular message.  
`MAC`s add assurance how cryptographic checksoum is calculated    
`KDF` Key Derivation Functions  

### Authenicated Modes , Key Wrapping, SealdObject
- `AE` Authenticated Encryption  
- `AEAD` - Authenticated Encryption with Associated Date  
- `Encrypt-and-MAC`  
- `MAC-then-Encrypt`  
- `Enctypt-then-MAC`   

- `GCM` Galois/Counter Mode  
### Password Based Key Gemeratin and Key splittig
- `PBKDF` - password based key derivation functions.
Taking somethimg easy to remember and producing an effective summetric key. `PBE` - Passwoed Based Encryption  
2013 - 2015 `hashing competition` run on the Internet. `Argon2` the winner  
-`SCRYPT`  

### Signatures  
- `Digital signature` (deterministic and not-deterministic)  
[`Digest Algorithm`](https://en.wikipedia.org/wiki/Cryptographic_hash_function#SHA-3) - SHA-1 SHA-256 SHA3-523  
[`DSA`](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) - Digital Signature Algorithm  
`ECDSA` - DSA ove Elliptic Curve  
`DDSA` - deterministic DSA  
`RSA` 



##TODO
- `BouncyCastleProvider` - explore this class (why it is used for DigestMessage)







## resources 
 [OpenPGP message format rfc4880](https://tools.ietf.org/html/rfc4880)  
 [buld you own pgp](https://andrewhalle.github.io/build-your-own/gpg)  
 



