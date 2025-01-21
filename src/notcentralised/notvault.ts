/* 
 SPDX-License-Identifier: MIT
 NotVault SDK for Typescript v0.9.2069 (notvault.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { Contract, Signer, PopulatedTransaction, utils, providers } from 'ethers';

import * as EthCrypto from "eth-crypto";

import ConfidentialGroup from './abi/ConfidentialGroup.json';
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

export type WalletDB = {
    // layerc.privatebalances
    // privateBalanceOf: (address: string, groupId: string, vaultAddress: string, denomination: string, obligor: string) => Promise<string>
    // setPrivateBalance: (address: string, groupId: string, vaultAddress: string, denomination: string, obligor: string, amount: string) => Promise<void>
    
    // layerc.privateamounts
    privateAmountOf: (vaultAddress: string, address: string, idHash: string | bigint) => Promise<string>
    setPrivateAmount: (sender: string, vaultAddress: string, address: string, idHash: string, amount: string) => Promise<void>
    
    getAddressByContactId: (id : string) => Promise<string>
    getPublicKey: (address: string) => Promise<string>

    registerKeys: (publicKey: string, encryptedPrivateKey: string, encryptedSecret: string, hashedContactId: string, encryptedContactId: string) => Promise<string>
    getEncryptedPrivateKey: (address: string) => Promise<string>
    getEncryptedContactId: (addres: string) => Promise<string>

    // layerc.valuedb
    getValue: (address: string, key: string) => Promise<string>
    setValue: (address: string, key: string, value: string) => Promise<void>
    
    // layerc.filedb
    getFileIndex: (address: string) => Promise<string>
    setFileIndex: (address: string, value: string) => Promise<void>
    
    // layerc.credentialdb
    getCredentialIndex: (address: string) => Promise<string>
    setCredentialIndex: (address: string, value: string) => Promise<void>

    setCredentialStatus: (hash: string, bool: any) => Promise<void>
}

export class NotVault
{
    confidentialWallet?: Contract;
    confidentialVault?: Contract;
    confidentialDeal?: Contract;
    confidentialOracle?: Contract;
    confidentialServiceBus?: Contract;
    confidentialGroup?: Contract;
 
    signer?: Signer;
    config?: Config;
    chainId?: string;

    db?: WalletDB;

    constructor(db?: WalletDB) { this.db = db; }
    
    init = (chainId?: string, signer?: Signer, config?: Config) => {
        this.signer = signer;
        
        this.chainId = !isNaN(+Number(chainId)) ? chainId : undefined;

        if(config){
            this.config                     = config;
            this.confidentialWallet         = chainId ? new Contract(this.config.contracts.walletAddress    , ConfidentialWallet.abi    , signer) : undefined;
            this.confidentialVault          = chainId ? new Contract(this.config.contracts.vaultAddress     , ConfidentialVault.abi     , signer) : undefined;
            this.confidentialDeal           = chainId ? new Contract(this.config.contracts.dealAddress      , ConfidentialDeal.abi      , signer) : undefined;
            this.confidentialOracle         = chainId ? new Contract(this.config.contracts.oracleAddress    , ConfidentialOracle.abi    , signer) : undefined;
            this.confidentialServiceBus     = chainId ? new Contract(this.config.contracts.serviceAddress   , ConfidentialServiceBus.abi, signer) : undefined;
            this.confidentialGroup          = chainId ? new Contract(this.config.contracts.groupAddress     , ConfidentialGroup.abi     , signer) : undefined;
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
                        this.privateKey = privateKey;
                        this.publicKey = EthCrypto.publicKeyByPrivateKey(this.privateKey);
            
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
            successCallback: (publicKey: string, contactId: string) => Promise<void>,
        ) => {
            if(!(this.confidentialWallet))
                throw new Error('Vault is not initialised');

            contactId = contactId.toLocaleLowerCase().trim();

            const _owner = EthCrypto.createIdentity();
            const ownerPublicKey = await encryptionPublicKeyCallback();

            const privateKey = _owner.privateKey;
            const encryptedSecret = ownerPublicKey === '' ? '' : metaMaskEncrypt(ownerPublicKey, secretKey);
            const encryptedPrivateKey = encryptedBySecret(secretKey, _owner.privateKey);
            const encryptedContactId = await encrypt(_owner.publicKey, contactId);
            const hashedContactId = EthCrypto.hash.keccak256(contactId);

            const tx = this.db ? await this.db.registerKeys(EthCrypto.publicKeyByPrivateKey(_owner.privateKey), encryptedPrivateKey, encryptedSecret, hashedContactId, encryptedContactId) : await this.confidentialWallet.registerKeys(EthCrypto.publicKeyByPrivateKey(_owner.privateKey), encryptedPrivateKey, encryptedSecret, hashedContactId, encryptedContactId);
            await tx.wait();
                    
            const publicKey = _owner.publicKey;
        
            this.address = address;
            this.privateKey = privateKey;
            this.publicKey = EthCrypto.publicKeyByPrivateKey(this.privateKey);

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
            const encryptedPrivateKey= this.db ? await this.db.getEncryptedPrivateKey(address) : await this.confidentialWallet.getEncryptedPrivateKey(address);
            const encryptedContactId= this.db ? await this.db.getEncryptedContactId(address) : await this.confidentialWallet.getEncryptedContactId(address);
            
            const privateKey = await decryptBySecret(secretKey, encryptedPrivateKey);
            const contactId = await decrypt(privateKey, encryptedContactId);
            
            this.address = address;
            
            this.privateKey = privateKey;
            this.publicKey = EthCrypto.publicKeyByPrivateKey(this.privateKey);
            this.contactId = contactId;
            
            await successCallback(this.publicKey, contactId);
    }

    enterData = async (
        address: string,
        privateKey: string,
        contactId: string,
    ) => {
        
        this.address = address;
        this.privateKey = privateKey;
        this.publicKey = EthCrypto.publicKeyByPrivateKey(this.privateKey);
            
        this.contactId = contactId;
}

    getWalletData = () => { 
        if(!this.privateKey)
            throw new Error('Not Key Setup')
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

        return this.db ? await this.db.getValue(this.address, key) : await this.confidentialWallet.getValue(this.address, key);
    }

    setValue = async (key: string, value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        const tx = this.db ? await this.db.setValue(this.address, key, value) : await this.confidentialWallet.setValue(key, value);
        if(tx.wait)
            await tx.wait();
    
    }

    setValueTx = async (key: string, value: string) : Promise<PopulatedTransaction> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        const tx = await this.confidentialWallet.populateTransaction.setValueMeta(this.address, key, value);
        return tx;
    }

    _setValue = async (key: string, value: string) : Promise<void> => {
        const tx = await this.setValueTx(key, value);
        const stx = await this.signTx(tx);
        await this.sendTx(stx.signature, this.signer?.provider);
    }

    signTx = async (tx: PopulatedTransaction, getNonce?: ()=>Promise<number>) => {
        if(!this.signer)
            throw new Error("No Signer");

        const nonce = getNonce ? await getNonce() : await this.signer.getTransactionCount();

        const signedTx = await this.signer.signTransaction({
            to: tx.to,
            data: tx.data,
            nonce: nonce, // Get the nonce for the owner,
            chainId: await this.signer.getChainId()
        });

        return {
            tx: tx,
            signature: signedTx
        };
    }

    signMetaTx = async (tx: PopulatedTransaction, getNonce?: () => Promise<number>) => {
        if (!(this.signer && this.address && tx.data)) throw new Error("No Signer");

        const messageHash = utils.solidityKeccak256(['bytes'], [tx.data]);
        
        const prefixedHash = utils.hashMessage(utils.arrayify(messageHash));
        // Sign the message hash
        const flatSig = await this.signer.signMessage(utils.arrayify(prefixedHash));

        return {
            tx: tx,
            messageHash: prefixedHash,
            signature: flatSig,
            address: this.address
        };
    }

    sendTx = async (stx: string, provider?: providers.Provider) => {
        const tx = await (provider ?? this.signer?.provider)?.sendTransaction(stx);
        await tx?.wait();
        return tx;
    }

    

    

    getFileIndex = async () : Promise<string> => {
        if(!(this.address && this.confidentialWallet))
            throw new Error('Vault is not initialised');

        return this.db ? await this.db.getFileIndex(this.address) : await this.confidentialWallet.getFileIndex(this.address);
    }

    setFileIndex = async (value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        const tx = this.db ? await this.db.setFileIndex(this.address, value) : await this.confidentialWallet.setFileIndex(value);
        if(tx.wait)
            await tx.wait();
    }

    setFileIndexTx = async (value: string) : Promise<PopulatedTransaction> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        const tx = await this.confidentialWallet.populateTransaction.setFileIndexMeta(this.address, value);
        return tx;
    }

    getCredentialIndex = async () : Promise<string> => {
        if(!(this.address && this.confidentialWallet))
            throw new Error('Vault is not initialised');

        return this.db ? await this.db.getCredentialIndex(this.address) : await this.confidentialWallet.getCredentialIndex(this.address);
    }

    setCredentialIndex = async (value: string) : Promise<void> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');
        
        const tx = this.db ? await this.db.setCredentialIndex(this.address, value) : await this.confidentialWallet.setCredentialIndex(value);
        if(tx.wait)
            await tx.wait();
    }

    setCredentialIndexTx = async (value: string) : Promise<PopulatedTransaction> => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');

        const tx = await this.confidentialWallet.populateTransaction.setCredentialIndexMeta(this.address, value);
        return tx;
    }

    getPublicKeyByContactId = async (owner: string) => {
        if(!(this.address && this.confidentialWallet && this.chainId))
            throw new Error('Vault is not initialised');
        
        const hashContactId = EthCrypto.hash.keccak256(owner.toLowerCase().trim());
        let destinationAddress = this.db ? await this.db.getAddressByContactId(hashContactId) : await this.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = owner;

        return this.db ? await this.db.getPublicKey(destinationAddress) : await this.confidentialWallet.getPublicKey(destinationAddress);
    }
}