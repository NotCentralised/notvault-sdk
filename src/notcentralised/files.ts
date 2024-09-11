/* 
 SPDX-License-Identifier: MIT
 Files SDK for Typescript v0.9.1669 (files.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import axios from 'axios';
import {  encrypt, encryptedBySecret } from './encryption';
import { v4 as uuidv4 } from 'uuid';

import { NotVault } from './notvault';

export type FileEntry = {
    cid: string, 
    secret: string, 
    meta: string, 
    created: number
}

export class Files
{
    vault: NotVault;
    constructor(vault: NotVault){
        this.vault = vault;
    }

    private fileCache : { [key: string]: any } = {};
    get = async (cid: string) : Promise<any> => {
        if(!this.vault.config)
            throw new Error('Vault is not initialised');

        if (!(cid in this.fileCache)){
            const res = await axios(this.vault.config.axios.get(cid));
            this.fileCache[cid] = res.data;
        }
        return this.fileCache[cid]
    }
    
    set = async (filename: string, encryptedB64: string, onUploadProgress?: any): Promise<string> => {
        if(!this.vault.config)
            throw new Error('Vault is not initialised');

        const fmData = new FormData();
        fmData.append("file", new Blob([encryptedB64], { type:`data:text/plain;base64`}), filename);
        const res = await axios(this.vault.config.axios.post(fmData, onUploadProgress));
        return res.data.IpfsHash;
    }

    del = async (cid: string) => {
        if(!this.vault.config)
            throw new Error('Vault is not initialised');
            
        await axios(this.vault.config.axios.del(cid));
    }

    upload = async (filename: string, dataB64: string, onUploadProgress?: any): Promise<FileEntry> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.publicKey)        
            throw new Error('Vault is not initialised');

        const secret = uuidv4();
        const encryptedB64 = encryptedBySecret(secret, dataB64);
        const fileCid = await this.set(filename, encryptedB64, onUploadProgress);

        const newFilePackage : FileEntry = { cid: fileCid, secret: secret, meta: filename, created: Date.now() };

        return newFilePackage;
    }

    list = async () : Promise<FileEntry[]> => {
        const fileCid = await this.vault.getFileIndex();
        if(fileCid == '')
            return [];

        const encryptedFileIndex = await this.get(fileCid);
        const fileIndex = await this.vault.decrypt(encryptedFileIndex);
        return JSON.parse(fileIndex);
    }

    add = async (filename: string, dataB64: string, onUploadProgress?: any): Promise<FileEntry[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.publicKey)        
            throw new Error('Vault is not initialised');

        try {
            try{
                const indexCid = await this.vault.getFileIndex();
                if(indexCid !== ''){
                    await this.del(indexCid);
                }
            }
            catch{}

            const newFilePackage = await this.upload(filename, dataB64, onUploadProgress);

            const files = await this.list();
            files.push(newFilePackage);

            const encryptedFileIndex = await encrypt(walletData.publicKey, JSON.stringify(files));
            const newIndexCid = await this.set(`index-${walletData.address}`, encryptedFileIndex);
            await this.vault.setFileIndex(newIndexCid);

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
                const indexCid = await this.vault.getFileIndex();
                if(indexCid !== ''){
                    await this.del(indexCid);
                }
            }
            catch(err: any){
                console.log(err);
            }

            try {
                await this.del(cid);
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
            const newIndexCid = await this.set(`index-${walletData.address}`, encryptedFileIndex);
            await this.vault.setFileIndex(newIndexCid);

            return files;
        } 
        catch (err: any) {
            console.log(err)
            return [];
        }
    }
 }