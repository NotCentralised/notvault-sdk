/*
Context: Typescript code for Initialisation

Must set environment variables:
- PUBLIC_URL
- PINATA_API_KEY
- PINATA_SECRET_API_KEY
*/

// 1) import necessary libraries
import { NotVault } from '@notcentralised/notvault-sdk';
import { ethers } from 'ethers';

// 2) instantiate the NotVault class
const vault = new NotVault();

// 3) create an JSON RPC connection
const customHttpProvider = new ethers.providers.JsonRpcProvider('... RPC Host ...');
const signer = new ethers.Wallet('... Private Key ...', customHttpProvider);

// 4) initialise the vault object by setting the tables above and the call-back functions that manage the file operations on IPFS.
vault.init('... Chain ID ...', signer);