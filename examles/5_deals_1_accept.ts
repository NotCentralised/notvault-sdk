/*
Context: Typescript code for accepting to a Deals
*/

// 1) import necessary libraries
import { NotVault, Tokens, Files, Deals } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Tokens classes
const vault = new NotVault();
const tokens = new Tokens(vault);
const files = new Files(vault);
const deals = new Deals(vault, tokens, files);

// 3) accept a deal
const hash_id = await deals.accept(
    '... Token Address ...',
    '... Email or Address ...',
    BigInt(1000) /* token amount */ * BigInt(10 ** 18) /* token decimal places */,
    BigInt(1), // deal ID
    '... Oracle Address ...',
    '... Owner Address ...',
    1, // Oracle Value
    1, // Oracle Key
    Math.floor(new Date('2023-08-10').getTime() / 1000), // date when payer can withdraw in unix format
    Math.floor(new Date('2024-08-10').getTime() / 1000), // date when payee can withdraw in unix format
);