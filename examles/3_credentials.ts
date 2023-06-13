/*
Context: Typescript code for managing Credentials
*/

// 1) import necessary libraries
import { NotVault, Files, FileEntry, Credentials, Schema, Proof } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault classes
const vault = new NotVault();
const files = new Files(vault);
const credentials = new Credentials(vault, files);

// 3) define a dataset that will be verified to create a credential
const passport_dataset : any = {
    id: 100,
    first_name: 'Pablo',
    last_name: 'Erchanfrit',
    dob: Math.floor(new Date('1990-08-10').getTime() / 1000), // unix format
    country: 'Liechtenstein'

};

// 4) define a schema for the credential
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

// 5) create a credential
const passport_credential = await credentials.issue(
    passport_dataset, 
    schema, 
    '... Owner Public Key ...', 
    '... Signature of source credential ...',
    true // If you wish to add this credential to the wallets list of credentials using the Files SDK.
);

// 6) create a query. In the example below, we are proving that the date of birth in Credential above is between specified values. Furthermore, we are sharing an aggregated hash of the Last Name and Country fields, as this example relates to a passport.
const query: { constraints:any, fields:any[] } = {
    constraints:{ // Upper and lower boundary constraints are only applied to numbers and dates
        dob: { lower: Math.floor(new Date('1980-08-10').getTime() / 1000), upper: Math.floor(new Date('1999-08-10').getTime() / 1000)},
    },
    fields:['last_name', 'country'] // Text data can only be verified by exact matches
};

// 7) generate a proof relating to a given query for a credential
const proof : Proof = await credentials.prove(query, passport_dataset, schema);

// 8) verify a credential
const isValid : boolean = await credentials.verify({
        last_name: 'Erchanfrit',
        country: 'Liechtenstein'
    }, 
    '... Public key of the issuer ...', 
    proof.schema, 
    proof.proof
);

// 9) list all credentials
const allCredentialsList = await credentials.list()

// 10) add new credential
const newCredentialsListAfterAdding : FileEntry[] = await credentials.add(
    `... any description of the dataset ...`,
    JSON.stringify(passport_dataset)
);

// 11) remove a Credential from a private list.
const newCredentialsListAfterRemoving : FileEntry[] = await credentials.remove(`... File CID in IPFS ...`);
