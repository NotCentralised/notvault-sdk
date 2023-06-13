/*
Context: Typescript code for managing events in a Confidential Service Bus
*/

// 1) import necessary libraries
import { NotVault, ServiceBus } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Tokens classes
const vault = new NotVault();
const servicebus = new ServiceBus(vault);

const key = BigInt(1);
const confidentialValue = BigInt(2);
// 3) add an event value
await servicebus.setValue(key, confidentialValue);

// 4) get an event value
const retrievedConfidentialValue : BigInt = await servicebus.getValue("... Wallet Address ...", key);