/* 
 SPDX-License-Identifier: MIT
 NotVault SDK for Typescript v0.4.3 (notvault.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { Contract, Signer } from 'ethers';

import * as EthCrypto from "eth-crypto";

import ConfidentialWallet from './abi/ConfidentialWallet.json';
import ConfidentialVault from './abi/ConfidentialVault.json';
import ConfidentialDeal from './abi/ConfidentialDeal.json';
import ConfidentialOracle from './abi/ConfidentialOracle.json';
import ConfidentialServiceBus from './abi/ConfidentialServiceBus.json';

import { zeroAddress } from './tokens';
import { getConfig, Config } from './config';

import { metaMaskEncrypt, metaMaskDecrypt, decrypt, encrypt, encryptedBySecret, decryptBySecret, encryptSign, sign } from './encryption';

(BigInt.prototype as any).toJSON = function () {
    return this.toString();
};

export const hederaList = ['295', '296', '297', '298']

export class NotVault
{
    confidentialWallet?: Contract;
    confidentialVault?: Contract;
    confidentialDeal?: Contract;
    confidentialOracle?: Contract;
    confidentialServiceBus?: Contract;
 
    signer?: Signer;
    config?: Config;
    chainId?: string;

    constructor() { }
    
    init = (chainId: string, signer: Signer, config?: Config) => {
        this.signer = signer;
        

        this.chainId = chainId;

        if(config){
            this.config = config;
            this.confidentialWallet = new Contract(this.config.contracts.walletAddress, ConfidentialWallet.abi, signer);
            this.confidentialVault = new Contract(this.config.contracts.vaultAddress, ConfidentialVault.abi, signer);
            this.confidentialDeal = new Contract(this.config.contracts.dealAddress, ConfidentialDeal.abi, signer);
            this.confidentialOracle = new Contract(this.config.contracts.oracleAddress, ConfidentialOracle.abi, signer);
            this.confidentialServiceBus = new Contract(this.config.contracts.serviceAddress, ConfidentialServiceBus.abi, signer);
        }
        else{
            this.config = getConfig(chainId)
        }
    }

    private address?: string;
    private publicKey?: string;
    private privateKey?: string;
    private contactId?: string;

    login = async (
            address: string, 
            decryptCallback: (encryptedSecret: string) => Promise<string>,
            successCallback: (publicKey: string, contactId: string) => Promise<void>,
            enterSecretCallback: () => Promise<void>,
            registerCallback: () => Promise<void>
        ) => {
            if(!this.confidentialWallet)
                throw new Error('Vault is not initialised');
            try{
                const publicKey: string = await this.confidentialWallet.getPublicKey(address);
                if(publicKey === ''){
                    await registerCallback();
                }
                else{
                    const encryptedSecret: string = await this.confidentialWallet.getEncryptedSecret(address);
                    const encryptedPrivateKey: string = await this.confidentialWallet.getEncryptedPrivateKey(address);
                    const encryptedContactId: string= await this.confidentialWallet.getEncryptedContactId(address);

                    const secretKey: string = encryptedSecret === '' ? '' : await metaMaskDecrypt(address, encryptedSecret, decryptCallback);
                    
                    if(secretKey === ''){
                        await enterSecretCallback();
                    }
                    else{
                        const privateKey: string = await decryptBySecret(secretKey, encryptedPrivateKey);
                        const contactId: string = await decrypt(privateKey, encryptedContactId);
                        
                        this.address = address;
                        this.publicKey = publicKey;
                        this.privateKey = privateKey;
                        this.contactId = contactId;

                        await successCallback(publicKey, contactId);
                    }
                }
            }
            catch (error: any){
                console.log(error);   
                await enterSecretCallback();
            }
    }

    register = async (
            address: string, 
            contactId: string, 
            secretKey: string,
            encryptionPublicKeyCallback: () => Promise<string>,
            decryptCallback: (encryptedSecret: string) => Promise<string>,
            successCallback: (publicKey: string, contactId: string) => Promise<void>,
        ) => {
            if(!(this.confidentialWallet && this.chainId))
                throw new Error('Vault is not initialised');

            contactId = contactId.toLocaleLowerCase().trim();

            let publicKey = await this.confidentialWallet.getPublicKey(address);

            let privateKey = '';
            if(publicKey === ''){
                const _owner = EthCrypto.createIdentity();
                const ownerPublicKey = await encryptionPublicKeyCallback();

                privateKey = _owner.privateKey;
                const encryptedSecret = ownerPublicKey === '' ? '' : metaMaskEncrypt(ownerPublicKey, secretKey);
                const encryptedPrivateKey = encryptedBySecret(secretKey, _owner.privateKey);
                const encryptedContactId = await encrypt(_owner.publicKey, contactId);
                const hashedContactId = EthCrypto.hash.keccak256(contactId);

                if(hederaList.includes(this.chainId)){
                    const tx = await this.confidentialWallet.registerKeys(EthCrypto.publicKeyByPrivateKey(_owner.privateKey), encryptedPrivateKey, encryptedSecret, hashedContactId, encryptedContactId, { gasLimit: BigInt(700_000/*684_397*/) });
                    await tx.wait();
                }
                else{
                    const tx = await this.confidentialWallet.registerKeys(EthCrypto.publicKeyByPrivateKey(_owner.privateKey), encryptedPrivateKey, encryptedSecret, hashedContactId, encryptedContactId);
                    await tx.wait();
                }
                
                publicKey = _owner.publicKey;
            }

            const encryptedPrivateKey= await this.confidentialWallet.getEncryptedPrivateKey(address);

            if(privateKey === '')
                privateKey = await metaMaskDecrypt(address, encryptedPrivateKey, decryptCallback);

            this.address = address;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.contactId = contactId;

            await successCallback(publicKey, contactId);
    }

    enterSecret = async (
            address: string,
            secretKey: string,
            successCallback: (publicKey: string, contactId: string) => Promise<void>,
        ) => {
            if(!this.confidentialWallet)
                throw new Error('Vault is not initialised');
            const publicKey = await this.confidentialWallet.getPublicKey(address);
            const encryptedPrivateKey= await this.confidentialWallet.getEncryptedPrivateKey(address);
            const encryptedContactId= await this.confidentialWallet.getEncryptedContactId(address);

            const privateKey = await decryptBySecret(secretKey, encryptedPrivateKey);
            const contactId = await decrypt(privateKey, encryptedContactId);

            this.address = address;
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.contactId = contactId;

            await successCallback(publicKey, contactId);
    }

    getWalletData = () => { 
        return {
            address: this.address,
            publicKey: this.publicKey,
            contactId: this.contactId
        }
    }

    decrypt = async (data : any) => {
        if(!this.privateKey)
            throw new Error('Vault is not initialised');

        return decrypt(this.privateKey, data);
    }

    encryptSign = async (toPublicKey: string, data : any) => {
        if(!this.privateKey)
            throw new Error('Vault is not initialised');

        return encryptSign(this.privateKey, toPublicKey, data);
    }

    sign = async (data : any) => {
        if(!this.privateKey)
            throw new Error('Vault is not initialised');

        return sign(this.privateKey, data);
    }
    
    getValue = async (key: string) : Promise<string> => {
        if(!(this.address && this.confidentialWallet))
            throw new Error('Vault is not initialised');

        return await this.confidentialWallet.getValue(this.address, key);
    }

    setValue = async (key: string, value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        if(hederaList.includes(this.chainId)){
            const tx = await this.confidentialWallet.setValue(key, value, { gasLimit: BigInt(200_000/*137_643*/) });
            await tx.wait();    
        }
        else{
            const tx = await this.confidentialWallet.setValue(key, value);
            await tx.wait();
        }
    }

    getFileIndex = async () : Promise<string> => {
        if(!(this.address && this.confidentialWallet))
            throw new Error('Vault is not initialised');

        return await this.confidentialWallet.getFileIndex(this.address);
    }

    setFileIndex = async (value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');
        
        if(hederaList.includes(this.chainId)){
            const tx = await this.confidentialWallet.setFileIndex(value, { gasLimit: BigInt(100_000/*90_313*/) });
            await tx.wait();    
        }
        else{
            const tx = await this.confidentialWallet.setFileIndex(value);
            await tx.wait();
        }
    }

    getCredentialIndex = async () : Promise<string> => {
        if(!(this.address && this.confidentialWallet))
            throw new Error('Vault is not initialised');

        return await this.confidentialWallet.getCredentialIndex(this.address);
    }

    setCredentialIndex = async (value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');
        
        if(hederaList.includes(this.chainId)){
            const tx = await this.confidentialWallet.setCredentialIndex(value, { gasLimit: BigInt(100_000/*90_313*/) });
            await tx.wait();    
        }
        else{
            const tx = await this.confidentialWallet.setCredentialIndex(value);
            await tx.wait();
        }
    }

    getPublicKeyByContactId = async (owner: string) => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');
        
        const hashContactId = EthCrypto.hash.keccak256(owner.toLowerCase().trim());
        let destinationAddress = await this.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = owner;

        return await this.confidentialWallet.getPublicKey(destinationAddress);
    }
}