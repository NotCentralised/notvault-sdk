/*
Context: Typescript code for managing Tokens
*/

// 1) import necessary libraries
import { NotVault, Tokens } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Tokens classes
const vault = new NotVault();
const tokens = new Tokens(vault);


// 3) deposit an amount into the vault's private balance
await tokens.deposit('...Token Address...', BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */);

// 4) send a confidential amount
const idHash = await tokens.send(
    '...Token Address...',
    '... Email or Receipient address ...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */
);

// 5) retrieve a confidential amount
await tokens.retreive(
    idHash,
    '...Token Address...'
);

// 6) withdraw an amount
await tokens.withdraw(
    '...Token Address...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */
);
