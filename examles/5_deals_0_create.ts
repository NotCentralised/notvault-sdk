/*
Context: Typescript code for creating Deals
*/

// 1) import necessary libraries
import { NotVault, Tokens, Files, Deals } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Tokens classes
const vault = new NotVault();
const tokens = new Tokens(vault);
const files = new Files(vault);
const deals = new Deals(vault, tokens, files);

// 3) create a deal
const deal_cid : string = await deals.create(
    '... Token Address ...', 
    '... Oracle Address ...',
    { 
        name: '... Deal Name ...', 
        counterpart: '... Email or Address ...',
        description: '... Deal Description ...', 
        notional: BigInt(10000),
        initial: BigInt(1000),
        unlock_sender: Math.floor(new Date('2023-08-10').getTime() / 1000), // unix format
        unlock_receiver: Math.floor(new Date('2024-08-10').getTime() / 1000), // unix format
        oracle_owner: '... Owner Address ...',
        oracle_key: 1,
        oracle_value: 1
    },
    {
        data: [{
            created: Math.floor(Date.now() / 1000), // unix format
            data: 'B64',
            name: 'filename'
        }]
    });
