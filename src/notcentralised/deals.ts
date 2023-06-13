/* 
 SPDX-License-Identifier: MIT
 Deals SDK for Typescript v0.4.3 (deals.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { decryptBySecret, encrypt, encryptedBySecret  } from './encryption';
import { Files } from './files';

import * as EthCrypto from "eth-crypto";

import { Tokens, SendRequest, zeroAddress } from './tokens';
import { NotVault, hederaList } from './notvault';
import { genProof } from './proof';

import { v4 as uuidv4 } from 'uuid';

export type Deal = {
    key: number,
    tokenId: bigint,
    name: string,
    owner: string,
    description: string,
    counterpart: string,
    denomination: string,
    notional: bigint,
    initial: bigint,
    files: {
        data: {
            created: number,
            data: string,
            name: string
        } []
    },
    payments: SendRequest[],

    oracle_address: string,
    oracle_owner: string,
    oracle_key: string | number,
    oracle_value: string | number,
    oracle_value_secret: string | number,

    unlock_sender: number,
    unlock_receiver: number,
    acceptedTime: number,
    createdTime: number,
    total_locked: bigint,
    accepted: boolean
}

export type DealPackege = {
    owner: string,
    counterpart: string,
    denomination: string,
    name: string,
    description: string,
    notional: bigint,
    initial: bigint,
    files: {
        data: {
            created: number,
            data: string,
            name: string
        } []
    },
    oracle_address: string,
    oracle_owner: string,
    oracle_key: string | number,
    oracle_value: string | number,
    oracle_value_secret: string | number,
    unlock_sender: number,
    unlock_receiver: number
}

export class Deals
{
    vault: NotVault
    tokens: Tokens;
    files: Files;

    constructor(vault: NotVault, tokens: Tokens, files: Files){
        this.vault = vault;
        this.tokens = tokens;
        this.files = files;
    }

    getAssets = async () : Promise<Deal[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialDeal)
            throw new Error('Vault is not initialised');

        const _deals: { tokenId: string, tokenUri:string, accepted:boolean, acceptedTime:number, createdTime:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
        if(_deals.length === 0)
            return [];

        return Promise.all(_deals
            .map((x:any) => { return { 'tokenId': BigInt(x.tokenId), 'tokenUri': x.tokenUri, 'accepted': x.accepted, 'acceptedTime': x.acceptedTime, 'createdTime': x.createdTime } })
            .map(async (x, i) => {
                if(!this.vault.confidentialDeal)
                    throw new Error('Vault is not initialised');

                const file = await this.files.get(x.tokenUri);

                const decryptedSecret = await this.vault.decrypt(file.owner);
                const decrypted = decryptBySecret(decryptedSecret, file.deal);
                const d = JSON.parse(decrypted);

                const tokenId = BigInt(x.tokenId);
                const payments: SendRequest[] = await this.vault.confidentialDeal.getSendRequestByDeal(tokenId);
                
                const total_locked = (await Promise.all(payments.filter(x=>x.active).map(async element => {
                    return BigInt(await this.vault.decrypt(element.private_receiver_amount));
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                // eslint-disable-next-line
                const { balance, decimals } = await this.tokens.tokenBalance(d.denomination);

                return {
                    key: i + 1,
                    tokenId: tokenId, 
                    name: d.name,
                    owner: d.owner,
                    description: d.description,
                    counterpart: d.counterpart,
                    denomination: d.denomination,
                    notional: BigInt(d.notional),
                    initial: BigInt(d.initial),
                    files: d.files,
                    payments: payments,

                    oracle_address: d.oracle_address,
                    oracle_owner: d.oracle_owner,
                    oracle_key: d.oracle_key,
                    oracle_value: d.oracle_value,
                    oracle_value_secret: d.oracle_value_secret,

                    unlock_sender: Number(d.unlock_sender),
                    unlock_receiver: Number(d.unlock_receiver),
                    acceptedTime: Number(x.acceptedTime),
                    createdTime: Number(x.createdTime),
                    total_locked: BigInt(total_locked) / decimals,
                    accepted: x.accepted
                }})
        );
    }
    
    getLiabilities = async () : Promise<Deal[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialDeal)
            throw new Error('Vault is not initialised');

        const _deals: { tokenId: string, tokenUri:string, accepted:boolean, acceptedTime:number, createdTime:number }[] = await this.vault.confidentialDeal.getDealByCounterpart(walletData.address);

        if(_deals.length === 0)
            return [];

        return Promise.all(_deals
            .map(x => { return { 'tokenId': BigInt(x.tokenId), 'tokenUri': x.tokenUri, 'accepted': x.accepted, 'acceptedTime': x.acceptedTime, 'createdTime': x.createdTime } })
            .map(async (x, i) => {
                if(!walletData.address)
                    throw new Error('Vault is not initialised');

                if(!this.vault.confidentialDeal)
                    throw new Error('Vault is not initialised');
        
                const files = await this.files.get(x.tokenUri);
                const decryptedSecret = await this.vault.decrypt(files.counterpart);
                const decrypted = decryptBySecret(decryptedSecret, files.deal);
                const d = JSON.parse(decrypted);
                
                const tokenId = BigInt(x.tokenId);
                const payments: SendRequest[] = await this.vault.confidentialDeal.getSendRequestByDeal(tokenId);
                
                const total_locked = (await Promise.all(payments.filter(x=>x.active).map(async element => {
                    return BigInt(await this.vault.decrypt(element.private_sender_amount))
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                // eslint-disable-next-line
                const { balance, decimals } = await this.tokens.tokenBalance(d.denomination);
    
                return {
                    key: -(i + 1),
                    tokenId: tokenId, 
                    name: d.name,
                    owner: d.owner,
                    description: d.description,
                    counterpart: d.counterpart,
                    denomination: d.denomination,
                    notional: BigInt(d.notional),
                    initial: BigInt(d.initial),
                    files: d.files,
                    payments: payments,
                    
                    oracle_address: d.oracle_address,
                    oracle_owner: d.oracle_owner,
                    oracle_key: d.oracle_key,
                    oracle_value: d.oracle_value,
                    oracle_value_secret: d.oracle_value_secret,
    
                    unlock_sender: Number(d.unlock_sender),
                    unlock_receiver: Number(d.unlock_receiver),
                    acceptedTime: Number(x.acceptedTime),
                    createdTime: Number(x.createdTime),
                    total_locked: total_locked / decimals,
                    accepted: x.accepted
                }})
        );
        
    }
    
    create = async (
            denominationAddress: string, 
            oracle_contract_address: string | undefined, 
            values: { 
                name: string, 
                counterpart: string, 
                description: string, 
                notional: bigint, 
                initial: bigint, 
                unlock_sender: number, 
                unlock_receiver: number, 
                oracle_owner: string, 
                oracle_key: string | number, 
                oracle_value: string | number
            }, 
            files: {
                data: {
                    created: number,
                    data: string,
                    name: string
                } []
            }
        ) : Promise<string> => {

            const walletData = this.vault.getWalletData();
            if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
                throw new Error('Vault is not initialised');
            
            const hashContactId = EthCrypto.hash.keccak256(values.counterpart.toLowerCase().trim());
            let destinationAddress = await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
            if(destinationAddress === zeroAddress)
                destinationAddress = values.counterpart;
        
            let oracleOwnerAddress = zeroAddress;
            if(values.oracle_owner){
                const oracleOwnerId = EthCrypto.hash.keccak256(values.oracle_owner.toLowerCase().trim());
                oracleOwnerAddress = await this.vault.confidentialWallet.getAddressByContactId(oracleOwnerId);
                if(oracleOwnerAddress === zeroAddress)
                    oracleOwnerAddress = values.oracle_owner;
            }
        
            const proof = !values.oracle_key || values.oracle_key === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: values.oracle_key, value: values.oracle_value });

            let deal : DealPackege = {
                owner: walletData.address,
                counterpart: destinationAddress,
                denomination: denominationAddress,
                name: values.name,
                description: values.description,
                notional: values.notional,
                initial: values.initial,
                files: files,
                oracle_address: oracle_contract_address ? oracle_contract_address : this.vault.confidentialOracle ? this.vault.confidentialOracle.address.toString() : zeroAddress,
                oracle_owner: oracleOwnerAddress,
                oracle_key: proof.inputs[1],
                oracle_value: proof.inputs[0],
                oracle_value_secret: values.oracle_value,
                unlock_sender: values.unlock_sender ? values.unlock_sender : 0,
                unlock_receiver: values.unlock_receiver ? values.unlock_receiver : 0
            }
        
            let dealPackage = JSON.stringify(deal);
        
            const counterPublicKey = await this.vault.confidentialWallet.getPublicKey(destinationAddress);
        
            const secret = uuidv4();
            const encryptedDealBySecret = encryptedBySecret(secret, dealPackage);
        
            const ownerEncryptedSecret = await encrypt(walletData.publicKey, secret);
            const counterEncryptedSecret = await encrypt(counterPublicKey, secret);
        
            const encryptedDeal = JSON.stringify({ owner: ownerEncryptedSecret, counterpart: counterEncryptedSecret, deal: encryptedDealBySecret }); 

            const cid = await this.files.set('deal.json', encryptedDeal);

            const b = await this.tokens.getBalance(denominationAddress);

            const proofAgree = await genProof(this.vault, 'minCommitment', { amount: BigInt(deal.initial) * BigInt(b.decimals), minAmount: BigInt(deal.initial) * BigInt(b.decimals), oracle_owner: deal.oracle_owner, oracle_key: deal.oracle_key, oracle_value: deal.oracle_value, unlock_sender: deal.unlock_sender, unlock_receiver: deal.unlock_receiver });
        
            if(hederaList.includes(this.vault.chainId)){
                const tx = await this.vault.confidentialDeal.safeMint(destinationAddress, proofAgree.inputs[1], proofAgree.inputs[2], cid, { gasLimit: BigInt(325_000/*303_191*/) });
                await tx.wait();
            }
            else{
                const tx = await this.vault.confidentialDeal.safeMint(destinationAddress, proofAgree.inputs[1], proofAgree.inputs[2], cid);
                await tx.wait();
            }
        
            return cid;
    }

    accept = async (
            denomination: string, 
            destination: string, 
            amount: bigint, 
            dealId: BigInt, 
            oracleAddress: string, 
            oracleOwner: string, 
            oracleKey: number, 
            oracleValue: number, 
            unlockSender: number, 
            unlockReceiver:number
        ) : Promise<string> => {
            if(!(this.vault.confidentialDeal && this.vault.chainId))
                throw new Error('Vault is not initialised');

            return this.tokens.send(denomination, destination, amount, dealId, oracleAddress, oracleOwner, oracleKey, oracleValue, unlockSender, unlockReceiver);
    }

    approve = async (key: string, value: string) : Promise<void> =>  {
        if(!(this.vault.confidentialOracle && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const proof = await genProof(this.vault, 'approver', { key: key, value: value});

        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialOracle.setValue(proof.solidityProof, proof.inputs, { gasLimit: BigInt(300_000/*291_582*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialOracle.setValue(proof.solidityProof, proof.inputs);
            await tx.wait();
        }
    }
}