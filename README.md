# NotVault &nbsp; &nbsp; | &nbsp; &nbsp; The Self-Sovereignty SDK

__NotVault__ is an open-source SDK that enables the rapid and safe development of self-sovereign data workflows. __NotVault__ enables confidential commerce / payments, token transfers, file management and the use of verifiable credentials. The toolkit simplifies the implementation of Zero Knowledge Proof (ZKP) technology, while applying best practices for encryption, decentralisation and peer-to-peer / operations for all data.

**NotVaul** is analogous to a wallet since it allows users to link a contact ID like an email to their wallet in a private way. Furthermore, the wallet creates a new public / private key pair which is used to encrypt and sign data within the ecosystem, without needing access to the keys of the ETH wallet (Metamask) which is typically not accessible through the API. The contact ID allows a more user-friendly way of connecting to other identities. Instead of needing to input a wallet address, users can instead input an email for example.

The key principles are to use the following as much as possible:
- **Peer-to-peer**: in order to mitigate single point of failure risks.
- **Encryption**: to ensure confidentiality
- **Zero Knowledge Proofs**: to minimise data foot print when communicating

Builders using __NotVault__ benefit from a rich toolkit of functionality in the form of smart contracts and client-side [typescript](https://www.typescriptlang.org) modules that include:
- **Wallet**: Stores encrypted keys and encrypted metadata.
- **Credentials**: [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) credental proof generation and verification.
- **Vault**: manage confidential token balances and transfers.
- **Files**: enables a self-sovereign and encrypted file storage capability through [IPFS](https://ipfs.tech).
- **Commercial Deals**: enable the life-cycle management of transactional / contractual agreements including their financial settlement and self-custody escrows of payment amounts through a peer-to-peer, self-custody platform.
- **Service Bus**: enables a confidential messaging service that ensures the integrity regarding of timestamp, source and underlying message using a [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof).

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