/*
Context: Typescript code for reading balances of Tokens
*/

// 1) import necessary libraries
import { NotVault, Tokens, Balance } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Tokens classes
const vault = new NotVault();
const tokens = new Tokens(vault);

// 3) check the various balances a given address has in the vault.
const balance : Balance = await tokens.getBalance('...Token Address...');

// 4) private or confidential balance
console.log('Private or Confidential Balance', balance.privateBalance);

// 5) public balance
console.log('Public Balance', balance.balance);

// 6) Locked outgoing balanced
balance.lockedIn.forEach(element => {
    console.log('Locked Out', element);
});

// 7) Locked incoming balanced
balance.lockedIn.forEach(element => {
    console.log('Locked In', element);
});


