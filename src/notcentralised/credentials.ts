/* 
 SPDX-License-Identifier: MIT
 Documents SDK for Typescript v0.4.0 (credentials.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/
import { NotVault } from './notvault';
import { genProof, verifyProof } from './proof';
import { recoverSignature, encrypt } from './encryption'
import { FileEntry, Files } from './files';

interface IIndexable { [key: string]: any }

export const proofConfig: { [key: string]: { text: number, numbers: number } } = {
    textData: { text: 1800, numbers: 0 },
    textExpiryData: { text: 1780, numbers: 1 },
    numericalData: { text: 30, numbers: 100 },
    alphaNumericalData: { text: 350, numbers: 75 }
}

export type Schema = {
    id: string;
    type: string;
    fields: {
        id: string;
        name: string;
        type: "string" | "number" | "date";
    }[];
};

export type EncodedData = {
    schema: Schema,
    data: any[];
    code: number[];
    constraint_upper: any[];
    constraint_lower: any[];
}

export type Credential = {
    schema: Schema,
    confidential: {
        issuer: string;
        owner: string;
    };
    id: string;
    hash: string;
    source: string;
}

export type Proof = {
    proof: {
        proof: string;
        solidityProof: string;
        inputs: string[];
    };
    signature: string;
}

export class Credentials
{
    vault: NotVault;
    files: Files;

    constructor(vault: NotVault, files: Files){ this.vault = vault; this.files = files; }

    private encodeData = (rawData: any, schema: Schema) : EncodedData => {
        let keys = Object.keys(rawData)
        
        const data = schema.fields.map((key, i)=>{
            const value = keys.includes(key.id) && typeof (rawData as IIndexable)[key.id] !== 'object' ? (rawData as IIndexable)[key.id] : 0;
            return {
                index: i,
                key: key.id,
                value: value,
                type: key.type
            }
        });

        const numbers = data.filter(x => x.type === "number" || x.type === "date");
        const texts = data.filter(x => x.type === "string");

        let encodedNumbers = [];
        let codeNumbers = [];
        let constraint_upper = [];
        let constraint_lower = [];
        for(let i = 0; i < proofConfig[schema.type].numbers; i++){
            if(i < numbers.length){
                encodedNumbers.push(numbers[i].value);
                constraint_upper.push(numbers[i].value);
                constraint_lower.push(numbers[i].value);
            }
            else{
                encodedNumbers.push(0);
                constraint_upper.push(0);
                constraint_lower.push(0);
            }
                
            codeNumbers.push(1);
        }

        let encodedTexts = [];
        let codeTexts = [];
        for(let i = 0; i < proofConfig[schema.type].text; i++){
            if(i < texts.length && texts[i].value && texts[i].value.length > 0)
                encodedTexts.push(strToNumber(texts[i].value));
                
            else
                encodedTexts.push(0);
                
            codeTexts.push(1);
        }

        return {
            schema: schema,
            data: encodedNumbers.concat(encodedTexts),
            code: codeNumbers.concat(codeTexts),
            constraint_upper: constraint_upper,
            constraint_lower: constraint_lower
        }
    }

    issue = async (rawData: any, schema: Schema, owner?: string, source?: string, Add?: boolean): Promise<Credential> => {
        
        const wallet = this.vault.getWalletData();
        if(!(wallet.publicKey && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const encodedDocument = this.encodeData(rawData, schema);

        let initialOwnerReference = owner ? owner.toLowerCase().trim() : '';

        if(owner){
            owner = await this.vault.getPublicKeyByContactId(owner);
        }

        const proof = await genProof(this.vault, schema.type, {
            data: encodedDocument.data,
            code: encodedDocument.code,
            constraint_upper: encodedDocument.constraint_upper,
            constraint_lower: encodedDocument.constraint_lower
        });

        const hash =  proof.inputs[0];

        const signed = await this.vault.sign(hash);
        const issuerPrivateMessage = await encrypt(wallet.publicKey, rawData);
        const ownerPrivateMessage = owner ? await encrypt(owner, rawData) : '';

        const issuedCredential = {
            schema: schema,
            confidential: {
                issuer: issuerPrivateMessage,
                owner: ownerPrivateMessage
            },
            id: signed.signature,
            hash: hash,
            source: source || signed.signature
        };

        if(Add === true){
            await this.vault.confidentialWallet.setCredentialStatus(hash, true);
            await this.add(JSON.stringify({ owner: initialOwnerReference, id: issuedCredential.id, type: schema.id }), JSON.stringify(issuedCredential));
        }
        
        return issuedCredential;
    }

    prove = async (query: any, rawData: any, schema: Schema) : Promise<Proof> => {
        
        const wallet = this.vault.getWalletData();
        if(!wallet.publicKey)
            throw new Error('Vault is not initialised');

        const encodedDocument = this.encodeData(rawData, schema);

        let credentialsObject : any = {}
        credentialsObject = {};
        credentialsObject.id = schema.id;
        credentialsObject.schema = schema;
            
        credentialsObject['fields']={}
        schema.fields.forEach(field => {
            credentialsObject['fields'][field.id] = field;
        })
        
        const keys = Object.keys(credentialsObject.fields);
        const constraints = query.constraints ? Object.keys(query.constraints) : [];

        const data = keys.map((key, i)=>{
            return {
                value: key,
                type: credentialsObject.fields[key].type,
                code: query.fields.includes(key) || constraints.includes(key) ? 1 : 0,
                constraint: constraints.includes(key) ? (query.constraints as IIndexable)[key] : { upper: (2 ** 36 - 1), lower: 0 }
            }
        });

    
        const numbers = data.filter(x => x.type === 'number' || x.type === 'date');
        const texts = data.filter(x => x.type == 'string');

        let codeNumbers = [];
        let constraint_upper = [];
        let constraint_lower = [];
        for(let i = 0; i < proofConfig[schema.type].numbers; i++){
            if(i < numbers.length){
                codeNumbers.push(numbers[i].code);
                constraint_upper.push(numbers[i].constraint ? numbers[i].constraint.upper : 0);
                constraint_lower.push(numbers[i].constraint ? numbers[i].constraint.lower : 0);
            }
            else{
                codeNumbers.push(0);
                constraint_upper.push(0);
                constraint_lower.push(0);
            }
        }

        let codeTexts = [];
        for(let i = 0; i < proofConfig[schema.type].text; i++){
            if(i < texts.length)
                codeTexts.push(texts[i].code);
                
            else
                codeTexts.push(0);
        }


        const proof = await genProof(this.vault, schema.type, {
            data: encodedDocument.data,
            code: codeNumbers.concat(codeTexts),
            constraint_upper: constraint_upper,
            constraint_lower: constraint_lower
        });

        const signature = await this.vault.sign(proof);

        return {
            proof: proof,
            signature: signature.signature
        };
    }

    verify = async (rawData: any, signer: string, schema: Schema, proof: any) : Promise<boolean> => {

        const r = recoverSignature({ message: proof.proof, signature: proof.signature })
        const check = await verifyProof(this.vault, schema.type, proof.proof);

        if(check && r.signer == signer){


            const encodedDocument = this.encodeData(rawData, schema);

            let names = encodedDocument.schema.fields.filter(x => x.type === 'number' || x.type === 'date').map(x => x.name);
            let dataNames = Object.keys(rawData);

            dataNames.forEach(n => {
                if(names.includes(n))
                    throw new Error('Numerical values cannot be specified');
            });
            
            const _proof = await genProof(this.vault, schema.type, {
                data: encodedDocument.data,
                code: encodedDocument.code,
                constraint_upper: encodedDocument.constraint_upper,
                constraint_lower: encodedDocument.constraint_lower
            });

            return proof.proof.inputs[2] === _proof.inputs[2];
        }

        return false;
    }

    list = async () : Promise<FileEntry[]> => {
        const fileCid = await this.vault.getCredentialIndex();
        if(fileCid == '')
            return [];

        const encryptedFileIndex = await this.files.get(fileCid);
        const fileIndex = await this.vault.decrypt(encryptedFileIndex);

        return JSON.parse(fileIndex);
    }

    add = async (filename: string, dataB64: string, onUploadProgress?: any): Promise<FileEntry[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.publicKey)        
            throw new Error('Vault is not initialised');

        try {
            try{
                const indexCid = await this.vault.getCredentialIndex();
                if(indexCid !== ''){
                    await this.files.del(indexCid);
                }
            }
            catch{}

            const newFilePackage = await this.files.upload(filename, dataB64, onUploadProgress);

            const files = await this.list();
            files.push(newFilePackage);

            const encryptedFileIndex = await encrypt(walletData.publicKey, JSON.stringify(files));
            const newIndexCid = await this.files.set(`credential-${walletData.address}`, encryptedFileIndex);
            await this.vault.setCredentialIndex(newIndexCid);

            return files;
        } 
        catch (err: any) {
            console.log(err)
            return [];
        }
    }

    remove = async (cid: string): Promise<FileEntry[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.publicKey)        
            throw new Error('Vault is not initialised');

        try {
            try {
                const indexCid = await this.vault.getCredentialIndex();
                if(indexCid !== ''){
                    await this.files.del(indexCid);
                }
            }
            catch(err: any){
                console.log(err);
            }

            try {
                await this.files.del(cid);
            }
            catch(err: any){
                console.log(err);
            }
            
            const _files = await this.list();
            let files: FileEntry[] = [];
            _files.forEach((val: any) => {
                if(val.cid !== cid) files.push(Object.assign({}, val))
            }); 

            const encryptedFileIndex = await encrypt(walletData.publicKey, JSON.stringify(files));
            const newIndexCid = await this.files.set(`credential-${walletData.address}`, encryptedFileIndex);
            await this.vault.setCredentialIndex(newIndexCid);

            return files;
        } 
        catch (err: any) {
            console.log(err)
            return [];
        }
    }
}

/**
 * Splits a string into an array of short strings (felts). A Cairo short string (felt) represents up to 31 utf-8 characters.
 * @param {string} str - The string to convert
 * @returns {bigint[]} - The string converted as an array of short strings as felts
 */
export const strToFeltArr = (str: string): BigInt[] => {
    const size = Math.ceil(str.length / 31);
    const arr = Array(size);

    let offset = 0;
    for (let i = 0; i < size; i++) {
        const substr = str.substring(offset, offset + 31).split("");
        const ss = substr.reduce(
            (memo, c) => memo + c.charCodeAt(0).toString(16),
            ""
        );
        arr[i] = BigInt("0x" + ss);
        offset += 31;
    }
    return arr;
}

/**
 * Converts an array of utf-8 numerical short strings into a readable string
 * @param {bigint[]} felts - The array of encoded short strings
 * @returns {string} - The readable string
 */
export const feltArrToStr = (felts: bigint[]): string => {
    return felts.reduce(
        (memo, felt) => memo + Buffer.from(felt.toString(16), "hex").toString(),
        ""
    );
}

export const strToNumber = (str: string): BigInt => {
    if(str.length > 31)
        throw new Error("string too long");

    const substr = str.split("");
    const ss = substr.reduce(
        (memo, c) => memo + c.charCodeAt(0).toString(16),
        ""
    );
    return BigInt("0x" + ss);
}