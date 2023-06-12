# NotVault &nbsp; &nbsp; | &nbsp; &nbsp; The Self-Sovereignty SDK

__NotVault__ is an open-source SDK that enables the rapid and safe development of self-sovereign data workflows. __NotVault__ enables confidential commerce / payments, token transfers, file management and the use of verifiable credentials. The toolkit simplifies the implementation of Zero Knowledge Proof (ZKP) technology, while applying best practices for encryption, decentralisation and peer-to-peer / operations for all data.

**NotVaul** is analogous to a wallet since it allows users to link a contact ID like an email to their wallet in a private way. Furthermore, the wallet creates a new public / private key pair which is used to encrypt and sign data within the ecosystem, without needing access to the keys of the ETH wallet (Metamask) which is typically not accessible through the API. The contact ID allows a more user-friendly way of connecting to other identities. Instead of needing to input a wallet address, users can instead input an email for example.

Builders using __NotVault__ benefit from a rich toolkit of functionality in the form of smart contracts and client-side [typescript](https://www.typescriptlang.org) modules that include:
- **Wallet**: Stores encrypted keys and encrypted metadata.
- **Credentials**: [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) credental proof generation and verification.
- **Vault**: manage confidential token balances and transfers.
- **Files**: enables a self-sovereign and encrypted file storage capability through [IPFS](https://ipfs.tech).
- **Commercial Deals**: enable the life-cycle management of transactional / contractual agreements including their financial settlement and self-custody escrows of payment amounts through a peer-to-peer, self-custody platform.

# Table of Contents
1. [Technical Overview](#technical_overview)
2. [Workflows](#workflows)
    - [Files](#workflows-files)
    - [Credentials](#workflows-credentials)
    - [Tokens](#workflows-tokens)
    - [Deals](#workflows-deals)
3. [SDK](#sdk)
    - [Initialise](#sdk-init)
    - [Register](#sdk-register)
    - [Files](#sdk-files)
    - [Credentials](#sdk-credentials)
    - [Tokens](#sdk-tokens)
    - [Deals](#sdk-deals)
4. [Deployed Contracts](#contract_addresses)
4. [Building](#building)


<div id='technical_overview'></div>

# Technical Overview
Confidential interactions are achieved through [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) verifications and [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) / [Public Key Encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) while their consistency and integrity is ensured through the transparency and immutability of blockchains. The architecture is a set of [Solidity](https://soliditylang.org) smart contracts that run on an [EVM](https://ethereum.org/en/developers/docs/evm/) compatible L1 and a Javascript [npm](https://www.npmjs.com) package that achieves:
- The obfuscation of fungible token balances through the [Poseidon](https://www.poseidon-hash.info) hash. Please note that only balances and the value of transfers is kept private. Neither the identity, source nor destination of the transfers relating to this token are private.
- The confidential storage and indexing of files onto [IPFS](https://ipfs.tech). Each file is encrypted with its own secret key using the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm.
- The verification of data integrity is a necessity for a functional, real world workflows in a trustless environment.
- The verification of data integrity through Credential workflows using [zkSNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof).

The code is divided into three main sections:
- [Typescript](https://www.typescriptlang.org) [NPM](https://www.npmjs.com) package: where encryption, proof generation and connectivity to both blockchains and [IPFS](https://ipfs.tech) occurs.
- [Solidity](https://soliditylang.org) smart contracts that define the vault, balances and transactional logic.
- [Circom](https://docs.circom.io) circuits that define the zero knowledge proof logic.

<div id='workflows'></div>

# Workflows <a name="workflows"></a>

__NotVault__ delivers self-sovereignty to numerous workflows that depend on storing files, transferring tokens, contractual / commercial agreements, verification of credentials and confidential data. In this section, we will discuss each workflow separately.



<div id='workflows-files'></div>

## Files SDK
The storage of and access to files through censorship-resistant and confidential technologies is essential to many applications. 

### Core Features:

This SDK harnesses cutting-edge technologies to deliver:

- **Censorship Resistance:** Utilizing the InterPlanetary File System ([IPFS](https://ipfs.tech)), a peer-to-peer file storage protocol, NotVault ensures your file data's resistance to censorship.

- **Confidentiality:** By implementing a Single Key Encryption methodology rooted in the Advanced Encryption Standard ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)) algorithm, NotVault guarantees the confidentiality of your files. This method creates a unique secret for each file, which is then used to encrypt the file, enabling efficient and confidential file distribution.

- **Private File List:** NotVault empowers each user with a private list of their files uploaded to IPFS. This list serves as a reference and includes:
    - File Name
    - Upload Date
    - Secret Encryption Key

### Workflow

Using NotVault, you can create workflows with the following steps:

- **Upload:** When a file is selected for upload, the following process is initiated:
    1. NotVault generates a UUID-based random key.
    2. This key is used to encrypt the file via the [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) algorithm.
    3. The encrypted file is then sent to [IPFS](https://ipfs.tech).
    4. Keep in mind, the file departs from the NotVault runtime only after encryption.

- **Listing:** Users can access their private file list, returning a list of names, upload dates, and secret encryption keys.

- **Retrieval:** Users can fetch a file from [IPFS](https://ipfs.tech) and decrypt it within the NotVault runtime using the corresponding secret key. This design ensures the reduction of potential content leaks.

- **Deletion:** Users can remove a file from their private list and unpin it from [IPFS](https://ipfs.tech).

> Important: Full confidentiality can only be attained by refraining from sharing the data itself, but rather by sharing cryptographic derivates of the confidential data. When a dataset is accessible to more than one person, managing the data's footprint becomes a challenge.


<div id='workflows-credentials'></div>

## Credentials
**NotVault** enables developers to create robust and secure data integrity verification systems. This feature is critical in developing functional, real-world workflows in trustless environments.

### Objects in the Workflow

Three primary objects are involved in this workflow:

- **Dataset**: This is a collection of data, the utility of which depends on the integrity of its contents.
- **Credential**: This is an object derived from the Dataset that contains additional information about the Dataset's validity and integrity.
- **Query**: This is a set of questions concerning the validity and integrity of a Credential.

### Roles in the Workflow

There are three roles in this workflow:

- **Person**: This can be an individual or entity that relates to or is the subject of a certain Dataset.
- **Issuer**: An individual or entity that attests to the validity of a Person's Dataset. The Issuer creates a Credential, which is an atomic Dataset that has been verified, encrypted, and signed.
- **Verifier**: An individual or entity that wishes to verify that a Query relating to a Credential is true.

### Workflow Steps

Here is the step-by-step process of this workflow:

1. **Dataset Creation**: A Person creates a Dataset that is dependable on the integrity of its contents. An example of such a Dataset is a Passport, where its utility is tied to its recognized integrity.

2. **Credential Creation**: An Issuer verifies the integrity of the Person's Dataset and generates a Credential. This new object contains an encrypted version of the Dataset that is signed by the Issuer. For instance, in the Passport example, the Issuer would be the specific government responsible for issuing the passport.

3. **Query Creation**: A Verifier who wishes to check if the Dataset matches specific criteria or features creates a Query outlining these constraints. The Verifier then shares the Query with the Person who owns the Credential. In the Passport example, the Verifier might be a border control officer who checks the validity of the passport.

4. **Proof Generation**: The Person generates a proof showing that their Credential meets the constraints or criteria specified in the Query. This proof is then sent to the Verifier.

5. **Proof Verification**: The Verifier validates the proof. It's important to note that the underlying Credential or data is never shared throughout this workflow—only the Query criteria and the proof corresponding to the Query.

This functionality of **NotVault** offers a robust method to verify data integrity without exposing the actual data, thereby maintaining the privacy and security of the information. Developers can use this functionality to build a wide range of applications, from identity verification to secure data access controls.

---

<div id='workflows-tokens'></div>

## Tokens SDK

**NotVault** ensures the confidential management and transaction of tokens, utilizing both censorship-resistant technologies and smart contracts known as 'The Vault'. 

### Key Features

Here are some core features provided by the Token SDK:

- **Token Life-cycle Management**: NotVault allows you to manage the entire life-cycle of token transactions with ease and high-level security.

- **The Vault Smart Contract**: The Vault stores hash values of token balances instead of conventional numerical values. This further promotes secure and private token transactions.

- **Zero Knowledge Proofs**: zkSNARKs or Zero Knowledge Proofs ensure that balance updates remain confidential yet consistent, bolstering the privacy of transactions.

- **Asynchronous Transfer Pattern**: NotVault adopts an asynchronous transfer pattern for private transfers. Unlike synchronous ERC20 transfers, these transfers require the receiver's acceptance before completion.

## Roles in the Token Workflow

In a **NotVault** token transaction workflow, two roles are crucial:

- **Sender**
- **Receiver**

### Workflow Steps

Below is a step-by-step walkthrough of a token transaction using NotVault:

1. **Deposit**: The sender deposits tokens from their public standard balance.
2. **zkSNARK Proof Generation by Sender**: Before a sender can transfer tokens, they generate a zk proof. This verifies that the sender knows their balance before the transfer and ensures the transferred amount is less than or equal to the available balance, avoiding double spending.
3. **Send Request**: The transferred amount is locked in The Vault smart contract as a Send Request, identified by a unique ID.
4. **Balance Update by Receiver**: When ready to accept the transfer, the receiver identifies the Send Request through its unique ID and updates their balance in The Vault.
5. **zkSNARK Proof Generation by Receiver**: To update their balance, the receiver generates a zk proof, verifying that they know the transferred amount and their balance before the update.
6. **Withdrawal**: Finally, the receiver withdraws the accepted amount from their private balance to their public standard balance.

### A Use Case Scenario

To put things into perspective, here's an example scenario of token workflows in NotVault:

- Owner A (sender) has 1000 tokens in their public balance. They deposit 100 of these tokens into their private balance within The Vault.
- Owner A's balance is now 100 tokens, represented on-chain as a hash.
- Owner A calculates their new balance after sending 10 tokens, and creates a new hash for the remaining 90 tokens.
- Using zkSNARK, Owner A verifies the balance update's consistency and updates their on-chain balance in The Vault, replacing the old hash with the new one.
- Owner A initiates a Send Request, locking the 10 tokens in it.
- Owner B (receiver), upon identifying the Send Request through its unique ID, calculates their new balance after adding the transferred tokens, and creates a new balance hash.
- Owner B creates a zkSNARK proof to verify their new balance hash is indeed the old balance plus the transferred amount.
- Owner B updates their on-chain balance in The Vault using the proof.
- Finally, the smart contract invalidates the Send Request's key to ensure it's spent only once.

-----

<div id='workflows-deals'></div>

## Deal

**NotVault** offers the ability to digitise term sheets and payment schedules for commercial or contractual relationships through smart contracts, streamlining commercial relationships and augmenting security and efficiency.

These relationships can exist between any parties - natural persons or legal entities such as corporations.

### What is a Deal?

A 'Deal' in **NotVault** is a digital representation of a term sheet consisting of deliverables and payment schedules. Payments are governed by programmed rules which act as prerequisites for the release of payments. Upon the start of the agreement, collateral is locked into 'The Vault' and utilized to satisfy the payments when their conditions are triggered.

> **Note**: Both term sheets and payment amounts maintain confidentiality. Term sheets are encrypted and only visible to the participants of the trade or commercial agreement. Payment amounts are confidential, achieved using the same methods as detailed in the Token Workflows.

### Roles in the Workflow

There are two primary roles in this workflow:

- **Payor**
- **Payee**

## Workflow Steps

Here is the step-by-step process to leverage **NotVault**'s smart contract term sheet and payment functionalities:

1. **Term Negotiation**: The payee and the payor negotiate and agree on the terms of a deal.
2. **Term Sheet Creation**: The payee generates a digital term sheet and payment schedule, which includes the initial collateral.
3. **Payment Conditions Definition**: During the creation and minting of the term sheet, the payee states the programmed payment conditions.
4. **Term Sheet Agreement**: The payor agrees to the digital term sheet and payment terms.
5. **Collateral Lock-In**: The payor locks in the initial collateral as per the payment terms, shifting tokens into the digital escrow account.
6. **Payment Release**: As the payment conditions are met, the collateralised amounts are unlocked and made available to the payee for withdrawal.

### Payment Conditions

The payment release conditions include:

- The payee can withdraw after a certain date.
- The payor can cancel payments that have not been withdrawn after a certain date.
- The payee can withdraw when an approved oracle feed reaches a certain value.

---


<div id='sdk'></div>

# SDK
Engaging with __NotVault__ can be done through two methods:
- Typescript SDK downloadable as an [NPM](https://www.npmjs.com/package/@notcentralised/notvault-sdk) package.
```Shell
    npm i @notcentralised/notvault-sdk
```

<div id='sdk-init'></div>

## Initialise NotVault

In order to begin using **NotVault** within your TypeScript projects, you will need to initialise the library correctly. This initialisation process sets up the necessary connections and providers for the library's operations, particularly for interacting with IPFS and the Ethereum blockchain via JSON-RPC.

### Environment Variables

Prior to initializing **NotVault**, you'll need to ensure the following environment variables are set:

1. `PUBLIC_URL`
2. `PINATA_API_KEY`
3. `PINATA_SECRET_API_KEY`

These are critical for the functioning of IPFS file operations and the connectivity with Pinata.

### Initialization Steps

To initialise **NotVault** in a TypeScript environment, follow the steps below:

1. **Import the necessary libraries**:
    ```typescript
    import { NotVault } from '@notcentralised/notvault-sdk';
    import { ethers } from 'ethers';
    ```

2. **Instantiate the NotVault class**:
    ```typescript
    const vault = new NotVault();
    ```

3. **Create an JSON RPC connection**:
    - Set up a new instance of `JsonRpcProvider` from the `ethers` library. You need to pass in your RPC Host URL to the `JsonRpcProvider` constructor.
    - Create a `signer` by creating a new instance of the `Wallet` class from the `ethers` library. Pass in your private key and the custom HttpProvider instance.
    ```typescript
    const customHttpProvider = new ethers.providers.JsonRpcProvider('... RPC Host ...');
    const signer = new ethers.Wallet('... Private Key ...', customHttpProvider);
    ```

4. **Initialise the vault object**: Now, using the `.init` function of the `vault` instance, pass in your Chain ID and the `signer` instance created in the previous step.
    ```typescript
    vault.init('... Chain ID ...', signer);
    ```

After successfully following these steps, your **NotVault** instance is set up and ready for file operations on IPFS and transactions on an EVM blockchain.

<div id='sdk-register'></div>

## Register and Generate Keys

Once you've initialised your **NotVault** library as detailed in the previous section, you're now ready to register an account and perform key generation.

To register an account and generate keys in a TypeScript environment, follow the steps below:

1. **Import the necessary libraries**:
    ```typescript
    import { NotVault } from '@notcentralised/notvault-sdk';
    ```

2. **Instantiate the NotVault class**:
    ```typescript
    const vault = new NotVault();
    ```

3. **Register the contact ID and keys**:
   - Use the `.register` method of the `vault` instance to register the account. This method takes in several parameters and callback functions to facilitate the registration process.
   - The parameters for this method include the wallet address, email or 0xWallet, and the secret key. 
   - The callback functions include retrieving the public key from the crypto wallet, decrypting with the crypto wallet, and a success callback that logs the public key and contact ID.
    ```typescript
    await vault.register(
        '... Wallet Address ...', 
        '... Email or 0xWallet ...',
        '... Secret Key ...',
        async () => { return '... Public Key ...'; }, // Retrieve public key from crypto wallet    
        async (encryptedPrivateKey: string) => { return '... Private Key ...'; }, // Decrypt with crypt wallet
        async (publicKey: string, contactId: string) => { console.log('Success!', publicKey, contactId); } // Success
    );
    ```

With these steps, your account is registered in **NotVault** and your keys are properly set up for further operations. This registration process is an essential step for successfully using **NotVault** to perform secure and confidential operations on your data and tokens.



<div id='sdk-files'></div>

# Files SDK
The Files SDK offers developers the functionality of an encrypted IPFS drive. It creates a list of references and secret keys to files stored on IPFS, where each file is encrypted with its own secret. This way, if one secret key is compromised, there is no compromise of the entire drive.

> Note: The list of files and secrets is only visible to the Wallet.

Here is a step-by-step guide on how to work with files in NotVault using TypeScript:

1. **Import the necessary libraries**:
    ```typescript
    import { NotVault, Files, FileEntry } from '@notcentralised/notvault-sdk';
    ```

2. **Instantiate the NotVault and Files classes**:
    ```typescript
    const vault = new NotVault();
    const files = new Files(vault);
    ```

3. **Add a new file**:
    - Use the `add` method of the `files` instance to add a file to the vault.
    - The method requires the filename and the content of the file. The content should be in Base64 format when dealing with binary data.
    - The method also accepts a callback function that reports the progress of the upload operation.
    ```typescript
    const newFilesList : FileEntry[] = await files.add(
        '... File Name ...', 
        '... Super secret text, usually in Base64 format when dealing with binary data ...', 
        (event: any) => {
            const percent = Math.floor((event.loaded / event.total) * 100);
            console.log(`Progress ${percent}%`);
        }
    );
    ```

4. **Retrieve the contents of a file given its CID**:
    - Use the `get` method of the `files` instance to retrieve a file from the vault using its Content Identifier (CID).
    ```typescript
    const retrievedFile : FileEntry = await files.get(`... File CID in IPFS ...`);
    ```

5. **List all the files linked to a specific wallet**:
    - Use the `list` method of the `files` instance to retrieve a list of all files linked to the specific wallet in the vault.
    ```typescript
    const allFiles : FileEntry[] = await files.list();
    ```

6. **Remove a file from a private list**:
    - Use the `remove` method of the `files` instance to remove a file from the vault using its Content Identifier (CID).
    ```typescript
    const newFilesAfterRemoval : FileEntry[] = await files.remove(`... File CID in IPFS ...`);
    ```

By following these steps, you can manage your files within the NotVault environment securely and efficiently.

---
<div id='sdk-credentials'></div>

# Credentials SDK
The Credentials SDK offers developers a way to manage the life-cycle of credentials including creation, proving and verification. 
The SDK also enables the storage of credentials using the Files SDK. The list of credentials is ONLY visible to the Wallet owner and is used for storage purposes only.

*Note: The length of each entry in the Credential is constrained by a maximum of 32 characters*

1. **Instantiating the NotVault classes:**

```typescript
const vault = new NotVault();
const files = new Files(vault);
const credentials = new Credentials(vault, files);
```
With these statements, we instantiate the `NotVault`, `Files`, and `Credentials` classes, providing the necessary foundations for credential operations.

2. **Defining a dataset:** 

Here, we define a dataset that will be verified to create a credential. The example below describes a passport dataset.

```typescript
const passport_dataset : any = {
    id: 100,
    first_name: 'Pablo',
    last_name: 'Erchanfrit',
    dob: Math.floor(new Date('1990-08-10').getTime() / 1000), // unix format
    country: 'Liechtenstein'
};
```

3. **Defining a schema for the credential:** 

We create a schema defining the structure of the credential.

```typescript
const schema : Schema = {
    id: 'passport',
    type: 'alphaNumericalData',
    fields: [
        {
            id: 'id',
            name: 'Passport Number',
            type: 'number'
        },
        {
            id: 'first_name',
            name: 'First Name',
            type: 'string'
        },
        {
            id: 'last_name',
            name: 'Last Name',
            type: 'string'
        },
        {
            id: 'dob',
            name: 'Date of Birth',
            type: 'date'
        },
        {
            id: 'country',
            name: 'Country',
            type: 'string'
        }
    ]
};
```

4. **Issuing a credential:** 

Issuing a Credential is the process of creating a cryptographic dataset which is derived from an initial dataset. The Credential is an attestation of the integrity of the original dataset.


```typescript
const passport_credential = await credentials.issue(
    passport_dataset, 
    schema, 
    '... Owner Public Key ...', 
    '... Signature of source credential ...',
    true // If you wish to add this credential to the wallets list of credentials using the Files SDK.
);
```

5. **Creating a query:** 

A query with constraints or criteria is necessary to generate a proof. We are proving that a Credential respects certain constraints. In the example below, we are proving that the date of birth in Credential above is between specified values. Furthermore, we are sharing an aggregated hash of the Last Name and Country fields, as this example relates to a passport.

Upper and lower boundary constraints are only applied to numbers and dates. Text data can only be verified by exact matches. Read more on this in the verification section below.

The proof will not be generated if the numerical data is not within the ranges stated in the constraints.

```typescript
const query: { constraints:any, fields:any[] } = {
    constraints:{ // Upper and lower boundary constraints are only applied to numbers and dates
        dob: { lower: Math.floor(new Date('1980-08-10').getTime() / 1000), upper: Math.floor(new Date('1999-08-10').getTime() / 1000)},
    },
    fields:['last_name', 'country'] // Text data can only be verified by exact matches
};
```

6. **Generating a proof:** 

A query with constraints or criteria is necessary to generate a proof. We are proving that a Credential respects certain constraints. In the example below, we are proving that the date of birth in Credential above is between specified values. Furthermore, we are sharing an aggregated hash of the Last Name and Country fields, as this example relates to a passport.

Upper and lower boundary constraints are only applied to numbers and dates. Text data can only be verified by exact matches. Read more on this in the verification section below.

The proof will not be generated if the numerical data is not within the ranges stated in the constraints.

```typescript
const proof : Proof = await credentials.prove(query, passport_dataset, schema);
```

7. **Verifying a credential:** 

Verifying a proof requires the values of the **fields** above. As mentioned, proofs are only generated if the numerical constraints are met. The proof will contain an aggregated hash of the text data.

The verification happens when the verifier creates an aggregated hash of the text values, which they expect the credential to contain. The first parameter below contains this information and the verification function will only return **true** if this information matches the information implicitly contained in the proof.

```typescript
const isValid : boolean = await credentials.verify({
        last_name: 'Erchanfrit',
        country: 'Liechtenstein'
    }, 
    '... Public key of the issuer ...', 
    proof.schema, 
    proof.proof
);
```

8. **Listing all credentials:** 

We fetch all credentials.

```typescript
const allCredentialsList = await credentials.list();
```

9. **Adding a new credential:** 

We add a new credential to the list.

```typescript
const newCredentialsListAfterAdding : FileEntry[] = await credentials.add(
    `... any description of the dataset ...`,
    JSON.stringify(passport_dataset)
);
```

10. **Removing a credential:** 

We eliminate a credential from the private list.

```typescript
const newCredentialsListAfterRemoving : FileEntry[] = await credentials.remove(`... File CID in IPFS ...`);
```

Please refer to the original TypeScript code context for a detailed breakdown of the parameters required for each function.

---


<div id='sdk-tokens'></div>

# Tokens SDK

The operations covered here include depositing an amount into the vault's private balance, sending a confidential amount, retrieving a confidential amount, and withdrawing an amount from the vault.

First, ensure you've imported the required libraries:

```typescript
import { NotVault, Tokens } from '@notcentralised/notvault-sdk';
```

## Instructions

1. **Instantiating the NotVault and Tokens classes:**

```typescript
const vault = new NotVault();
const tokens = new Tokens(vault);
```
This initializes the `NotVault` and `Tokens` classes, providing the groundwork for token operations.

2. **Depositing an amount into the vault's private balance:** 

```typescript
await tokens.deposit('...Token Address...', BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */);
```
This command deposits a specific amount into the vault's private balance. The amount is calculated as a product of the token amount and the token decimal places.

3. **Sending a confidential amount:** 

```typescript
const idHash = await tokens.send(
    '...Token Address...',
    '... Email or Receipient address ...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */
);
```
With this command, you can send a confidential amount to a recipient. The transaction id hash is stored for future reference.

4. **Retrieving a confidential amount:** 

```typescript
await tokens.retreive(
    idHash,
    '...Token Address...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */
);
```
This command allows for the retrieval of a confidential amount using the transaction id hash. This can be used in the event of a need for a transaction review or audit.

5. **Withdrawing an amount:** 

```typescript
await tokens.withdraw(
    '...Token Address...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */
);
```
This function permits you to withdraw a specified amount from the vault. This is useful for managing the flow of tokens and controlling the vault's balance.

Please refer to the original TypeScript code context for more granular detail on the parameters required for each function.

---

## Reading Token Balances

This section explains the steps to read various balances for a specific address using the NotVault SDK. This includes checking the private (confidential), public, locked outgoing, and locked incoming balances.

1. **Check the various balances a given address has in the vault:**

```typescript
const balance : Balance = await tokens.getBalance('...Token Address...');
```

This step fetches the `Balance` object for the given token address, which includes all different types of balances associated with the address.

2. **View the private or confidential balance:**

```typescript
console.log('Private or Confidential Balance', balance.privateBalance);
```

This logs the confidential balance, providing a view of the amount kept private in the vault.

3. **View the public balance:**

```typescript
console.log('Public Balance', balance.balance);
```

This logs the public balance associated with the token address, which indicates the publicly viewable amount.

4. **View the locked outgoing balances:**

```typescript
balance.lockedOut.forEach(element => {
    console.log('Locked Out', element);
});
```

This iterates over and logs each locked outgoing balance, providing visibility into amounts that are locked for outgoing transactions.

5. **View the locked incoming balances:**

```typescript
balance.lockedIn.forEach(element => {
    console.log('Locked In', element);
});
```

This iterates over and logs each locked incoming balance, which can provide insights into amounts locked for incoming transactions.



<div id='sdk-deals'></div>

# Deals SDK

The Deals SDK offers developers a way to digitise commercial agreement term sheets and payment terms through smart contracts.

## Create Deal

A deal is the representation of a term sheet with certain deliverables and associated payment schedules. Payments can have programmed rules attached for their release. Payments are initially locked into the vault upon the commencement of the agreement, prior to meeting the specific rules / tests allowing their release. Users can specify the value of the initial payments locked into the escrow function of the vault. This could be partial or complete collateralisation of the payments potentially due under the term sheet agreement.

The deal is created by the party expecting to be to be paid. Creation of the deal implied an acceptance to the terms by the payee, because otherwise, why would one create a deal with those terms?

```Typescript
    import { Deals, Files } from '@notcentralised/notvault-sdk';

    const files = new Files(vault);
    const deals = new Deals(vault, tokens, files);

    const deal = await deals.createDeal(
        '... Token Address ...', 
        '... Oracle Address ...',
        { 
            name: '... Deal Name ...', 
            counterpart: '... Email or Address ...',
            description: '... Deal Description ...', 
            notional: 10000,
            initial: 1000,
            unlock_sender: Math.floor(new Date('2023-08-10').getTime() / 1000), // unix format
            unlock_receiver: Math.floor(new Date('2024-08-10').getTime() / 1000), // unix format
            oracle_owner: '... Owner Address ...',
            oracle_key: 1,
            oracle_value: 1
        },
        {
            data: [{
                created: 1685512747,
                data: 'B64',
                name: 'filename'
            }]
        });
```

## Accept Deal
Once a deal has been created, the payor accepts the terms and payment schedule and creates a payment linked to the agreed upon initial collateral amount stated in the deal term sheet.

```Typescript
    const hash_id = await deals.accept(
        '... Token Address ...',
        '... Email or Address ...',
        BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */,
        1, // deal ID
        '... Oracle Address ...',
        '... Owner Address ...',
        1, // Oracle Value
        1, // Oracle Key
        Math.floor(new Date('2023-08-10').getTime() / 1000), // date when payer can withdraw in unix format
        Math.floor(new Date('2024-08-10').getTime() / 1000), // date when payee can withdraw in unix format
    );
```

<div id='contract_addresses'></div>

# Contract Addresses
The current contracts are in development and shouldn't be used in production at all.

**⚠️** WARNING! **⚠️** All of the contract addresses below will change as we iterate rapidly during these initial phases. Please keep a look out for changes in these addresses.

### Deployment Costs
|        | GOERLI Address                                                                                                               | SEPOLIA Address                                                                                                              | Deployment Gas |
|--------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------|
| Wallet | [0x274bBa8D9a813Cf2dc...](https://goerli.etherscan.io/address/0x274bBa8D9a813Cf2dcC77809E1FcC4276975603D) | [0xbf44E97CA5ea1A37AE...](https://sepolia.etherscan.io/address/0xbf44E97CA5ea1A37AEb74c0F717e9c32a1ee1985) | 1,162,239      |
| Vault  | [0x238B2a04490945419C...](https://goerli.etherscan.io/address/0x238B2a04490945419C27156316E03c12A17fC8D2) | [0x8d091FD5DBC8fF7d44...](https://sepolia.etherscan.io/address/0x8d091FD5DBC8fF7d440CD090a6f7fA2C1881f42E) | 5,041,627      |
| Deal   | [0x54Fc585d7319008aE5...](https://goerli.etherscan.io/address/0x54Fc585d7319008aE5B1352a945437c4276746E3) | [0x534f243a8C24d9F7fe...](https://sepolia.etherscan.io/address/0x534f243a8C24d9F7fe16571f74c6b1d30C448Ec2) | 4,328,511      |
| Oracle | [0x111bC62B663E3AE19E...](https://goerli.etherscan.io/address/0x111bC62B663E3AE19E03B14C91C0f35D6709b3c8) | [0xB4fF70Ba67854024Ed...](https://sepolia.etherscan.io/address/0xB4fF70Ba67854024EdbE8b2c0629642e69636945) |   693,393      |
| USDC   | [0x13c5D55aAADf431cf1...](https://goerli.etherscan.io/address/0x13c5D55aAADf431cf1C02bB18D197e90A4Fc7D9E) | [0x54ee808825BFfC235d...](https://sepolia.etherscan.io/address/0x54ee808825BFfC235d90F2F00AaC977A2Fd5F9Ad) | 1,410,952      |
| wETH   | [0x84a9F2717C7C4Bbe2A...](https://goerli.etherscan.io/address/0x84a9F2717C7C4Bbe2AC6946158c261A09822822b) | [0x1A93241D2640970D9B...](https://sepolia.etherscan.io/address/0x1A93241D2640970D9B2D520df96e307B9f8eF9dF) | 1,411,036      |
| wBTC   | [0x479290Ce0D67337c45...](https://goerli.etherscan.io/address/0x479290Ce0D67337c45b14e63afa21AABbeEDed2d) | [0xCB81DBD1Be0d68bc8a...](https://sepolia.etherscan.io/address/0xCB81DBD1Be0d68bc8a551c989A8067d08A3B371F) | 1,411,036      |

### Method Costs
|          | Methods       | Approx Gas | Gas Limit |
|----------|---------------|------------|-----------|
| Wallet   | registerKeys  | 684,397    | 700,000   |
| Wallet   | setValue      | 137,643    | 200,000   |
| Wallet   | setFileIndex  | 90,313     | 100,000   |
| Vault    | deposit       | 552,191    | 600,000   |
| Vault    | withdraw      | 374,927    | 400,000   |
| Vault    | createRequest | 1,152,414  | 1,200,000 |
| Vault    | acceptRequest | 618,821    | 650,000   |



<div id='building'></div>

# Building Steps
Building the entire repo requires a few steps.
- Install the necessary tools
- Build the circuits
- Build the evm project
- Deploy the contracts
- Build the sdk project
- Build the app

### Prerequisites
The compilation and development environment necessary are:
#### Rust
A fast and memory efficient language used by the [circom](https://docs.circom.io) compiler.

https://www.rust-lang.org
```shell
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```
#### Circom 2.0
The zero knowledge circuit development environment.

https://docs.circom.io
```shell
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```
#### SnarkJS
The zkSnark environment.

https://github.com/iden3/snarkjs
```shell
npm install -g snarkjs
```
Once the environment is correctly setup, you can proceed with compiling the cirtuits.

## Build the circuits
In the evm project compile the circuits using the following commands:
```shell
cd circuits
sh compile.sh
cd ...
```