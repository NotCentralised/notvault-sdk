# NotVault &nbsp; &nbsp; | &nbsp; &nbsp; The Self-Sovereignty SDK

The **NotVault** SDK is an open-source toolset designed for the swift and secure creation of self-sovereign data workflows. Its functionality spans multiple use cases, including confidential commerce and payments, token transfers, file management, and the application of verifiable credentials.
With a focus on streamlining the incorporation of Zero Knowledge Proof (ZKP) technology, NotVault emphasises best practices for encryption, decentralisation, and peer-to-peer operations in all data exchanges.

## Core Principles
NotVault operates on three fundamental principles:
- **Peer-to-Peer**: To mitigate risks associated with a single point of failure.
- **Encryption**: To maintain confidentiality at all times.
- Zero Knowledge Proofs: To minimise data footprints during communication.

The functionality of NotVault mirrors that of a wallet, facilitating the private linkage of a contact ID (such as an email) to a user's wallet. Additionally, it generates a new public/private key pair used for data encryption and signing within the ecosystem. This system negates the need to access the keys of the Ethereum wallet (typically inaccessible via API) and provides a more user-friendly method of connecting with other identities.

## Key Features
Developers leveraging NotVault can access a plethora of features including:
- **Wallet**: Safeguards encrypted keys and metadata.
- **Credentials**: Facilitates the generation and verification of [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) credential proofs.
- **Vault**: Manages confidential token balances and transfers.
- **Files**: Enables self-sovereign and encrypted file storage capability through [IPFS](https://ipfs.tech).
- **Commercial Deals**: Supports the lifecycle management of transactional or contractual agreements, including their financial settlement. It offers self-custody escrows of token payment amounts via a peer-to-peer platform.
- **Service Bus**: Provides a confidential messaging service, ensuring integrity of timestamp, source, and underlying message using a [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof).
Harness the power of **NotVault** SDK to expedite the development of secure, decentralised applications and services.

----

# Information
For more detailed information please go to our [GITBOOK](https://docs.notcentralised.com).

# Examples
Below is a list of Typescript examples:
- Initialise
    - [Initialise Simple](examles/0_initialise_0_simple.ts)
    - [Initialise Custom](examles/0_initialise_1_custom.ts)
- [Register](examles/1_register.ts)
- [Files](examles/2_files.ts)
- [Credentials](examles/3_credentials.ts)
- Tokens
    - [Tokens Life-cycle](examles/4_tokens_0_life_cycle.ts)
    - [Tokens Balances](examles/4_tokens_1_balances.ts)
- Deals
    - [Deal Creation](examles/5_deals_0_create.ts)
    - [Deal Acceptance](examles/5_deals_1_accept.ts)
- [Service Bus](examles/6_servicebus.ts)

# License

MIT License.