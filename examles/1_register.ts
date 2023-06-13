/*
Context: Typescript code for Registering account and key generation
*/

// 1) import necessary libraries
import { NotVault } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault class
const vault = new NotVault();

// 3) Registering the contact ID and keys
await vault.register(
    '... Wallet Address ...', 
    '... Email or 0xWallet ...',
    '... Secret Key ...',
    async () => { return '... Public Key ...'; }, // Retrieve public key from crypto wallet    
    async (encryptedPrivateKey: string) => { return '... Private Key ...'; }, // Decrypt with crypt wallet
    async (publicKey: string, contactId: string) => { console.log('Success!', publicKey, contactId); } // Success
);