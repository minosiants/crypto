## crypto

 * [Java Security Developer's Gude](https://docs.oacle.com/en/java/javase/15/security/index.html)  
 * [JDK JavaDoc](https://docs.oracle.com/en/java/javase/15/docs/api/index.html)  
 * [Bouncy Castle Home Page](https://www.bouncycastle.org/java.html)  
 * [Bouncy Castle source code](https://github.com/bcgit/bc-java)  

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
#### Block and stream ciphers

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











