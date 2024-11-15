 # Private-key agent 
 
The Private-key agent is a service that exposes a REST API for creating 
signatures and decrypting data using one or more private keys that it protects.
The Private-key agent service is intended to be used by other services that need
to sign and decrypt data, but do not want to handle the protection private keys
themselves, i.e. for security reasons. The idea is to have the private-key agent 
running in a different proces and user, possibly on different hosts machines, 
than the services that use it.

The Private-key agent service can be configured to use software keys, where the
private key is stored in a file on disk, or hardware keys, where the private key
is stored in a hardware security module (HSM) using PKCS#11. 
For the REST API that is exposed to the services, it does not matter whether a 
software key or a hardware key is used.

The Private-key agent only performs the private key operations. It does
not process the actual message/data that needs to be signed or decrypted.
E.g. When signing, it does not create the DigestInfo structure with
the hash of the message. When decrypting, it only unwraps the encryption key.
The rest of the signing an decryption processing is to be performed at the client. 
This choice keeps the private-key agent simple, the size of the REST API calls small, 
and aligns with the goal of the private-key agent to protect private keys.

The idea is to use the private-key agent from e.g.:
https://github.com/simplesamlphp/xml-security/blob/master/src/Backend/SignatureBackend.php
https://github.com/simplesamlphp/xml-security/blob/master/src/Backend/EncryptionBackend.php

A pool of workers is created to handle the private key operations for one or more keys. 
Each worker can be configured to use one of two signing backends:
1. OpenSSL. A software backend. The private keys reside in memory on
   on the signer, and are loaded from disk when the signer starts.
2. PKCS#11. A hardware backend. The private keys resides in a hardware
   security module (HSM). The signer communicates with the HSM(s) using
   the PKCS#11 (Cryptokey) protocol.

The private-key agent supports multiple clients.
Clients authenticate to the private-key agent using an OAuth 2.0 bearer token (RFC 6750).
and the private-key agent uses the error responses defined in RFC 6750. The intention is to
make the private-key agent usable in a OAuth 2.0 environment at a later date, if needed.

Each client can be allowed access to multiple private keys.
We could implement a more fine-grained access control, e.g. specifying which operations
a client is allowed to perform on a key, or adding such permissions to a key, but that 
does not seem to be needed at this time, and would make the private-key agent more complex.
Typical HSM backends do support some access control, e.g. (dis)allowing decryption and
signing operations that can be used.

The private-key agent only supports private key operations.
The goal is to support the operations that are required by SimpleSAMLphp
and OpenConext, keeping the private-key agent API simple, and to define
the interface such that only the data that needs to be signed or decrypted is exchanges.
We do not want to send XML documents, certificate etc to the private-key agent.

The following private key operations must be supported, because these are commonly used in SAML (xml-security):
- RSA: 
  - RSA PKCS#1 v1.5 signature (CKM_RSA_PKCS)
  - RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) 
  - RSA PKCS#1 OAEP decryption (CKM_RSA_PKCS_OAEP) 
More key types (e.g. from the ECC family) and key operations can be added in the future.
We could only support the RAW RSA operation, the downside is that this may conflict with
existing HSM policies that forbid the use of RAW RSA operations, and that it requires
the client to do all the signature preparation (padding) and removing and verifying the
padding after decryption. 
The upside is that this would allow the client to implement any signature and decryption 
scheme that it wants.
We could use the PKCS#11 interface, but for e.g. CKM_RSA_PKCS, that would require the client
to build an ASN.1 DigestInfo structure (and we'd still want to check that the client did 
the padding correctly).
For signing a sensible middle ground is to support the RSA PKCS#1 v1.5 signature and let the
client send the hash value and the hashing algorithm that was used and return the signature.
For decryption using RSA PKCS#1 v1.5 we return the decrypted value, which is the value of the 
symmetric (decryption) key when using http://www.w3.org/2001/04/xmlenc#rsa-1_5, this is the only 
information we have. The client can then use this to decrypt the data.
For decryption using RSA PKCS#1 OAEP we need additional information:
  - the mask generation function (MGF1) hash algorithm: sha1, sha224, sha256, sha384, sha412
  - Optionally the OAEP Parameters: label
OAEP Label is not typically used in the XML Encryption

# Configuration
- agent_name: The name of this agent

## Pool
One or more pools of workers can be created. Workers in a pool share the same
configuration. Their main purpose is to parallelize the private key operations to
increase throughput.

- pool_name: The name of the pool
- pool_type: "openssl" or "pkcs11"
- pool_size: The number of workers that are created in the pool
- pool_environment: (optional) environment variables to set for the worker
  processes in this pool. A pool inherits the environment of the signer.
  This option allows to set environment variables specific to this pool.
  Format: list of env1=value1 
  pkcs11 options:
  - pool_pkcs11_lib: Path to the PKCS#11 library to use
  - pool_pkcs11_slot: The PKCS#11 slot number to use
  - pool_pkcs11_pin: (optional) The user pin to use to authenticate to the 
  - token in <pool_pkcs11_slot>

keys: <list of keys>

### Key
One or more keys can be loaded in a Pool.
  - pool_key_type: rsa
  - pool_key_name: The name of the key, used by clients to refer to this key
                   The key_name must be unique within the pool
                   You can use the same key_name in multiple pools, in that case
                   the signer will evenly distribute the load over the workers in all the pools
                   where the key is available.
                   If multiple keys with the same name are used these MUST be that same private key.
                   The idea is that this allows multiple HSMs to be used for the same key
                   for performance or redundancy reasons.
Software options:
  - pool_key_file: The path to the private key file. For RSA that is a PEM RSA PRIVATE KEY file
  pkcs11 options:
  - pool_key_pkcs11_label: The label (CKA_LABEL) of the key to use
  - pool_key_pkcs11_key_id: The id (CKA_ID) of the key to use
    One of pool_pkcs11_label or pool_pkcs11_key_id must be set,
    if both are set, both are used to find the key.
    Exactly one key must match, if more than one key is found, the key is not loaded. 

 ## client
 - client_name: The name of the client
 - client_secret: The bearer token that the client must use to authenticate
 - client_keys: List of pool_key_name with the keys that this client is allowed
   to use


 # REST API

Responses may include additional fields, but the fields listed below are mandatory.
A client MUST check ignore any additional fields in the response.

 - POST /sign/{key_name}
   Authorization: Bearer <token>
   Encoding: application/json
 
   {
     "algorithm": "rsa-pkcs1-v1_5-sha256", "rsa-pkcs1-v1_5-sha1", etc
     "hash": "<Base64 string with the hash to put in the DigestInfo structure (data to sign)>"
   }
   Response (OK 200): Signature created successfully
Encoding: application/json
{
    "signature": "<Base64 string with the signature>"
}
   Response (wrong request 400): Missing or invalid parameters
   - error: Invalid request
   Response (authentication error 401): Invalid or missing bearer token
   - error: Authentication error
   Response (Access Denied 403): Unknown client or key, or client not allowed to use the key
   - error: Access Denied
   Response (Internal Server Error 500): Error creating the signature because of a server issue
   - error: Internal Server Error
   - 
 - POST /decrypt/{key_name}
   Authorization: Bearer <token>
   Encoding: application/json
   {
     "algorithm": "rsa-pkcs1-v1_5" or "rsa-pkcs1-oaep-mgf1-sha1", "rsa-pkcs1-oaep-mgf1-sha256",
     "encrypted_data": "<Base64 string with the encrypted data>"
   }
   Response (OK 200): Decryption successful
   Encoding: application/json
   {
       "decrypted_data": "<Base64 string with the decrypted data>"
   }

The POST returns rfc6750 3.1. Error Codes
- invalid_request (HTTP 400): A parameter is missing or invalid
- invalid_token (HTTP 401): The bearer token is missing or invalid
 E.g.:
     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="<agent_name>",
                       error="invalid_token",
                       error_description="The access token expired"

Other error codes:
- "access_denied" (HTTP 403): The client is not allowed to use the requested key, or the key does not exist
- "server_error" (HTTP 500): An error occurred on the server, e.g. because of a problem
  with a signing backend.
The error MAY include additional information about the error in the "message" field.
Same status code MUST be set in both the HTTP response and the JSON response

Encoding: application/json
{
   "status": 403,
   "error": "Access Denied",
   "message": "Optional message with more information for the client"
}

 - GET /health
   Response (OK 200): The signer is healthy
   - status: OK
   Response (Internal Server Error 500): The signer is not healthy
   - status: Internal Server Error

- GET /health/pool/{pool_name}
    Response (OK 200): The pool is healthy
    - status: OK
    Response (Internal Server Error 500): The pool is not healthy
    - status: Internal Server Error