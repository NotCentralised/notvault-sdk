/* 
 SPDX-License-Identifier: MIT
 Documents SDK for Typescript v0.9.1969 (credentials.ts)

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
        decimals?: number;
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
    confidential?: {
        issuer: string;
        owner: string;
    };
    id: string;
    hash: string;
    source: string;
}

export type Proof = {
    query: Record<string, any>,
    schema: Schema,
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
    files?: Files;

    constructor(vault: NotVault, files?: Files){ this.vault = vault; this.files = files; }

    issue = async (rawData: Record<string, any>, schema: { id?: string, type?: string, data?: Schema }, owner?: string, source?: string, chainMeta?: { read: boolean, write: boolean }): Promise<Credential> => {
  
        let { obj: dateObject, schema: _schema } = getObject(rawData, schema.data ? { id: schema.data.id, type: schema.data.type } : { id: schema.id ?? '', type: schema.type ?? ''});

        if(schema.data)
            _schema = schema.data;
      
        const encodedDocument = encodeData(dateObject, _schema);

        let initialOwnerReference = owner ? owner.toLowerCase().trim() : '';

        if(chainMeta?.read === true && owner){
            owner = await this.vault.getPublicKeyByContactId(owner);
        }

        const proof = await genProof(this.vault, _schema.type, {
            data: encodedDocument.data,
            code: encodedDocument.code,
            constraint_upper: encodedDocument.constraint_upper,
            constraint_lower: encodedDocument.constraint_lower,
            salt: strToFeltArr('0').concat(strToFeltArr('0'))
        });

        const hash =  proof.inputs[0];

        const wallet = this.vault.getWalletData();

        const signed = await this.vault.sign(source ? (hash + source) : hash);
        const issuerPrivateMessage = wallet.publicKey ? await encrypt(wallet.publicKey, dateObject) : '';
        const ownerPrivateMessage = owner ? await encrypt(owner, dateObject) : '';

        const issuedCredential = (wallet.publicKey === undefined || wallet.publicKey === null) && (owner === undefined || owner === null) ? {
            schema: _schema,
            confidential: {
                issuer: issuerPrivateMessage,
                owner: ownerPrivateMessage
            },
            id: signed.signature,
            hash: hash,
            source: source || signed.signature
        } : {
            schema: _schema,
            confidential: {
                issuer: issuerPrivateMessage,
                owner: ownerPrivateMessage
            },
            id: signed.signature,
            hash: hash,
            source: source || signed.signature
        };

        if(chainMeta?.write === true && this.vault.confidentialWallet){
            this.vault.db ? await this.vault.db.setCredentialStatus(hash, true) : await this.vault.confidentialWallet.setCredentialStatus(hash, true);
            await this.add(JSON.stringify({ owner: initialOwnerReference, id: issuedCredential.id, type: _schema.id }), JSON.stringify(issuedCredential));
        }
        
        return issuedCredential;
    }

    prove = async (query: Record<string, any>, salt: string, rawData: Record<string, any>, schema: Schema) : Promise<Proof> => {
        
        const wallet = this.vault.getWalletData();
        if(!wallet.publicKey)
            throw new Error('Vault is not initialised');

        
        let { obj: dateObject, schema: _ } = getObject(rawData, { id: schema.id, type: schema.type });

        const encodedDocument = encodeData(dateObject, schema);
        const proof = await generateProof(this.vault as NotVault, query, salt, schema, encodedDocument, false);
        const signature = await this.vault.sign(proof);
        
        return {
            query: query,
            proof: proof,
            schema: schema,
            signature: signature.signature
        };
    }

    verify = async (rawData: Record<string, any>, salt: string, proof: Proof, signer?: string) : Promise<boolean> => {

        const schema = proof.schema;

        let { obj: dateObject, schema: _ } = getObject(rawData, { id: schema.id, type: schema.type });
        
        let valuesCopy : Record<string, any> = {};
        schema.fields.forEach(field => {
            const type = field.type;
            if(type === 'string' && field.id in dateObject)
                valuesCopy[field.id] = dateObject[field.id];
        });

        let names = schema.fields.filter(x => x.type === 'number' || x.type === 'date').map(x => x.name);
        let dataNames = Object.keys(dateObject);

        dataNames.forEach(n => {
            if(names.includes(n))
                throw new Error('Numerical values cannot be specified');
        });

        const r = recoverSignature({ message: proof.proof, signature: proof.signature })

        const check = await verifyProof(this.vault, schema.type, proof.proof);

        if(check && r.signer == (signer !== undefined && signer !== null ? signer : r.signer)){

            const encodedDocument = encodeData(valuesCopy, schema);
            const _proof = await generateProof(this.vault as NotVault, proof.query, salt, schema, encodedDocument, true);
            
            return proof.proof.inputs[2] === _proof.inputs[2] && 
                proof.proof.inputs[3] === _proof.inputs[3] && 
                proof.proof.inputs[4] === _proof.inputs[4] && 
                proof.proof.inputs[5] === _proof.inputs[5];
        }

        return false;
    }

    list = async () : Promise<FileEntry[]> => {
        const fileCid = await this.vault.getCredentialIndex();
        if(fileCid == '')
            return [];

        if(!this.files)
            throw new Error('Files is not initialised');


        const encryptedFileIndex = await this.files.get(fileCid);
        const fileIndex = await this.vault.decrypt(encryptedFileIndex);

        return JSON.parse(fileIndex);
    }

    add = async (filename: string, dataB64: string, onUploadProgress?: any): Promise<FileEntry[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.publicKey)        
            throw new Error('Vault is not initialised');

        if(!this.files)
            throw new Error('Files is not initialised');


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

        if(!this.files)
            throw new Error('Files is not initialised');

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

const encodeData = (rawData: any, schema: Schema) : EncodedData => {
    let keys = Object.keys(rawData)
    
    const data = schema.fields.map((key, i)=>{
        const value = keys.includes(key.id) && typeof (rawData as IIndexable)[key.id] !== 'object' ? (rawData as IIndexable)[key.id] : undefined;
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
        if(i < numbers.length && numbers[i].value){
            const val = numbers[i].type === "date" ? Date.parse(numbers[i].value) : numbers[i].value;
            encodedNumbers.push(val);
            constraint_upper.push(val);
            constraint_lower.push(val);

            codeNumbers.push(1);
        }
        else{
            encodedNumbers.push(0);
            constraint_upper.push(0);
            constraint_lower.push(0);

            codeNumbers.push(0);
        }
    }

    let encodedTexts = [];
    let codeTexts = [];
    for(let i = 0; i < proofConfig[schema.type].text; i++){
        if(i < texts.length && texts[i].value && texts[i].value.length > 0) {
            encodedTexts.push(strToNumber(texts[i].value));

            codeTexts.push(1);
        }
        else {
            encodedTexts.push(0);

            codeTexts.push(0);
        }
    }

    return {
        schema: schema,
        data: encodedNumbers.concat(encodedTexts),
        code: codeNumbers.concat(codeTexts),
        constraint_upper: constraint_upper,
        constraint_lower: constraint_lower
    }
}

const generateProof = async (vault: NotVault, query: Record<string, any>, salt: string, schema: Schema, encodedDocument: EncodedData, verificationFlag: boolean) => {

    const _query = structureQuery(query, schema);

    let credentialsObject : any = {}
    credentialsObject = {};
    credentialsObject.id = schema.id;
    credentialsObject.schema = schema;
        
    credentialsObject['fields']={}
    schema.fields.forEach(field => {
        credentialsObject['fields'][field.id] = field;
    })
    
    const keys = Object.keys(credentialsObject.fields);
    const constraints = _query.constraints ? Object.keys(_query.constraints) : [];

    const data = keys.map((key, i)=>{

        const constraint = constraints.includes(key) ? (_query.constraints as IIndexable)[key] : { upper: (2 ** 36 - 1), lower: 0 };

        if(credentialsObject.fields[key].decimals < countDecimals(constraint.upper) || credentialsObject.fields[key].decimals < countDecimals(constraint.lower)){
            console.log(credentialsObject.fields[key].decimals, countDecimals(constraint.upper), countDecimals(constraint.lower))
            throw Error(`constraint decimals must equal schema's: ${key}`)
        }
        
        return {
            value: key,
            type: credentialsObject.fields[key].type,
            code: _query.fields.includes(key) || constraints.includes(key) ? 1 : 0,
            constraint: { upper: Math.round(constraint.upper * (10**credentialsObject.fields[key].decimals)), lower: Math.round(constraint.lower * (10**credentialsObject.fields[key].decimals)) }
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

    const saltArr = strToFeltArr(salt.length === 0 ? '0' : salt);

    const proof = await genProof(vault, schema.type, {
        data: encodedDocument.data,
        code: verificationFlag ? encodedDocument.code : codeNumbers.concat(codeTexts),
        // code: codeNumbers.concat(codeTexts),
        constraint_upper: constraint_upper,
        constraint_lower: constraint_lower,
        salt: saltArr.length >= 2 ? [saltArr[0], saltArr[1]] : [saltArr[0], saltArr[0]]
    });

    return proof;
}

const chunkString = (input: string, maxLength: number = 31): string[] => {
    const result: string[] = [];
    
    for (let i = 0; i < input.length; i += maxLength) {
        result.push(input.substring(i, i + maxLength));
    }

    return result;
}

export const unflattenObject = (flatObj: Record<string, any>):  Record<string, any> => {
    const result: any = {};

    const assignValue = (obj: any, keys: string[], value: any) => {
        const key = keys.shift();

        if (!key) return;

        if (keys.length === 0) {
            if (key.includes('%')) { // handle string chunks
                const [actualKey, index] = key.split('%');
                obj[actualKey] = (obj[actualKey] || "") + value;
            } else if(value) {
                obj[key] = value;
            }
        } else {
            if (!obj[key]) {
                // Check if the next key is numeric (for arrays) or not (for objects)
                const isNumeric = !isNaN(Number(keys[0]));
                obj[key] = isNumeric ? [] : {};
            }
            assignValue(obj[key], keys, value);
        }
    };

    for (const key in flatObj) {
        const keys = key.split('$');
        assignValue(result, keys, flatObj[key]);
    }

    return result;
}

export const flattenObject = (obj: Record<string, any>, queryFlag: boolean) => {
    
    const type = obj === null ? null : Array.isArray(obj) ? 'array' : typeof obj;

    if(obj === null || obj === undefined)
        return obj;

    if(type === 'string' || type === 'number' || type === 'boolean')
        return obj;
        
    let again = false;
    
    let newObj : Record<string, any> = {}
    Object.keys(obj).sort((a,b) => a.localeCompare(b)).map(x => {
        const type = obj[x] === null ? null : Array.isArray(obj[x]) ? 'array' : typeof obj[x];
        
        if(type !== null){

            if(type === 'object'){
                const _obj = obj[x];
                const keys = Object.keys(_obj);
                if(queryFlag && keys.length === 2 && !isNaN(+_obj.min) && !isNaN(+_obj.max))
                    newObj[x] = obj[x];
                else{
                    keys.map(y => {
                        const innerObj = _obj[y];
                        newObj[x + '$' + y] = flattenObject(innerObj, queryFlag);
                    })
                    again = true;
                }
            }

            else if(type === 'array'){
                const arr = obj[x];
                arr.forEach((element:any, i:number) => {
                    newObj[x + '$' + i] = flattenObject(element, queryFlag);
                });

                again = true;
            }
            else
                if (obj[x].length > 31){

                    const arr = chunkString(obj[x]);
                    arr.forEach((element:any, i:number) => {
                        newObj[x + '%' + i] = element;
                    });

                }
                else
                    newObj[x] = obj[x];
        }
    })

    if(again)
        newObj = flattenObject(newObj, queryFlag);

    return newObj;
}

const structureQuery = (query: Record<string,any>, schema: Schema) => {
    const fquery = flattenObject(query, true);

    const flatObj: Record<string, any> = {}
    schema.fields.forEach((x: any) => {
        flatObj[x.id] = x.type;
    });
    
    const stringArrKeys : Record<string,string[]> = {}
    Object.keys(flatObj)
    .filter(x => x.indexOf('%') > -1)
    .forEach(x => { 
        const key = x.substring(0, x.indexOf('%'));
        if(!(key in stringArrKeys))
            stringArrKeys[key] = [];
        stringArrKeys[key].push(x) 
    });

    const flatQuery: Record<string, any> = {}
                
    Object.keys(fquery).forEach(key => {
        if(fquery[key]){
            
            if(key in stringArrKeys) {
                stringArrKeys[key].forEach((y: any) => flatQuery[y] = fquery[key]);
            }
            // else if(Object.keys(fquery[key]).length === 2){
            //     if(!isNaN(+fquery[key].min) && !isNaN(+fquery[key].max))
            //         flatQuery[key] = fquery[key];
            //     else if(Array.isArray(fquery[key]) && typeof fquery[key][0] !== 'string')
            //         flatQuery[key] = [0, 1].map(i => new Date(fquery[key][i].unix() * 1000).toISOString());
            // }
            else if(typeof fquery[key] !== 'object')
                flatQuery[key] = fquery[key];
        }
    });

    let _query: { constraints:any, fields:string[] } = {
        constraints:{},
        fields:[]
    }

    Object.keys(flatQuery).forEach(key => {
        const value = flatQuery[key];
        if(value !== undefined){

            if(value.min !== undefined && value.max !== undefined) {
                _query.constraints[key] = {
                    upper: value.max,
                    lower: value.min
                };
            }
            else if(Object.keys(value).length === 0 && value) {
                _query.fields.push(key);
            }
            // else if(value.length === 2) {
            //     let min = Date.parse(value[0]);
            //     let max = Date.parse(value[1]);
            //     _query.constraints[key] = {
            //         upper: max,
            //         lower: min
            //     };
            // }
        }
    });

    return _query;
}

const isFloatButNotWholeNumber = (value: any): boolean => {
    return typeof value === 'number' && !Number.isInteger(value) && Number.isFinite(value);
}

const countDecimals = (value: number): number => {
    if (Math.floor(value) === value) {
        return 0; // No decimal places for whole numbers
    }

    const valueAsString = value.toString();
    const decimalPart = valueAsString.split('.')[1];

    return decimalPart ? decimalPart.length : 0;
}

const getObject = (rawData: Record<string, any>, schemaMeta: {id: string, type: string}) => {
    const flatObj = flattenObject(JSON.parse(JSON.stringify(unflattenObject(rawData))), false);
    
    const dateRegEx = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/;

    const schema: Schema = {
        id: schemaMeta.id,
        type: schemaMeta.type,
        fields: Object.keys(flatObj).map(x => {
            const type = x === null ? null : Array.isArray(x) ? 'array' : typeof flatObj[x];
            return {
                id: x,
                name: x,
                type: 
                    type === "string" && dateRegEx.test(flatObj[x]) ? 
                    "date" : 

                    type === "string" && !isNaN(+Number(flatObj[x]))&& isFinite(Number(flatObj[x])) ? 
                    "number" :

                    type === "number" ? 
                    "number" : 

                    "string",
                decimals: 
                    type === "string" && !isNaN(+Number(flatObj[x]))&& isFinite(Number(flatObj[x])) && isFloatButNotWholeNumber(Number(flatObj[x])) ? 
                    countDecimals(Number(flatObj[x])) : 

                    type === "number" && isFloatButNotWholeNumber(Number(flatObj[x])) ? 
                    countDecimals(Number(flatObj[x])) : 

                    0
            }
        })
    };

    let dateObject : Record<string, any> = {};
    Object.keys(flatObj).map(x => {
        let type = x === null ? null : Array.isArray(x) ? 'array' : typeof flatObj[x];
        type = 
            type === "string" && dateRegEx.test(flatObj[x]) ? 
            "date" : 

            type === "string" && !isNaN(+Number(flatObj[x])) && isFinite(Number(flatObj[x])) ? 
            "number" : 

            type === "number" ? 
            "number" : 

            "string"

        dateObject[x] = 
            type === "date" ? 
            new Date(Date.parse(flatObj[x])).toISOString() : 

            type === "number" && isFinite(Number(flatObj[x])) ? 

            Math.round(Number(flatObj[x]) * (10 ** countDecimals(Number(flatObj[x])))) :
            
            flatObj[x];
    })
    
    const constraints : Record<string, any> = {};
    schema.fields.forEach(x => {
        if(x.type !== 'string')
            constraints[x.id] = {
                upper: 1e10,
                lower: 0
            }
    });

    return {
        obj: dateObject,
        schema: schema
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