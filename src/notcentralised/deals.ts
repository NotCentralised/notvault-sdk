/* 
 SPDX-License-Identifier: MIT
 Deals SDK for Typescript v0.9.569 (deals.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { decryptBySecret, encrypt } from './encryption';
import { Files } from './files';

import { PopulatedTransaction } from 'ethers';

import * as EthCrypto from "eth-crypto";

import { Tokens, SendRequest, zeroAddress } from './tokens';
import { NotVault } from './notvault';
import { genProof } from './proof';

export type DealPackage = {
    counterpart: string,
    deal_address: string,
    deal_group_id: bigint,

    denomination: string,
    obligor: string,

    notional: bigint,
    expiry: number
    
    data: any,
    initial_payments?: {
        amount: bigint,

        oracle_address?: string,
        oracle_owner?: string,

        oracle_key_sender?: string | number,
        oracle_value_sender?: string | number,
        oracle_value_sender_secret?: string | number,

        oracle_key_recipient?: string | number,
        oracle_value_recipient?: string | number,
        oracle_value_recipient_secret?: string | number,

        unlock_sender?: number,
        unlock_receiver?: number,
    }[]
}

export type Deal = DealPackage & {
    key: number,
    payments: SendRequest[],

    meta: {
        accepted: number,
        cancelled_owner: number,
        cancelled_counterpart: number,
        created: number,
        total_locked: bigint
    }
}

export type DealStruct = {
    tokenId : bigint,
    tokenUri : string,
    created: number,
    cancelledOwner: number,
    cancelledCounterpart: number,
    accepted: number,
    expiry: number
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

    getDeal = async (id: BigInt, getFile?: (uri: string) => Promise<string>) : Promise<Deal> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialDeal)
            throw new Error('Vault is not initialised');

        const dealStruct = await await this.vault.confidentialDeal.getDealByID(id);

        let d : DealPackage | undefined = undefined;
            
        if(getFile){
            const file = await getFile(dealStruct.tokenUri);
            d = JSON.parse(file);
        }
        else{
            const file = await this.files.get(dealStruct.tokenUri);

            const decryptedSecret = await this.vault.decrypt(file.owner);
            const decrypted = decryptBySecret(decryptedSecret, file.deal);
            d = JSON.parse(decrypted);
        }

        
        const tokenId = BigInt(dealStruct.tokenId);
        const payments: SendRequest[] = await this.vault.confidentialDeal.getSendRequestByDeal(tokenId);
        
        const total_locked = (await Promise.all(payments.filter(x=>x.active).map(async element => {
            const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
            return BigInt(await this.vault.decrypt(privateAmount));
        }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

        if(!d)
            throw Error("Deal Not Found");

        return {
            ...d,
            key: 0,
            payments: payments,

            meta: {
                accepted: Number(dealStruct.accepted),
                cancelled_owner: Number(dealStruct.cancelledOwner),
                cancelled_counterpart: Number(dealStruct.cancelledCounterpart),
                created: Number(dealStruct.created),
                total_locked: BigInt(total_locked)
            }
        };
    }

    getAssets = async (getFile?: (uri: string) => Promise<string>) : Promise<Deal[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialDeal)
            throw new Error('Vault is not initialised');

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number, cancelledOwner:number, cancelledCounterpart:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);

        if(_deals.length === 0)
            return [];

        return Promise.all(_deals
            .map((x) => { return { 'tokenId': BigInt(x.tokenId), 'tokenUri': x.tokenUri, 'accepted': x.accepted, 'created': x.created, 'expiry': x.expiry, 'cancelled_owner': x.cancelledOwner, 'cancelled_counterpart': x.cancelledCounterpart } })
            .map(async (x, i) => {
                if(!this.vault.confidentialDeal)
                    throw new Error('Vault is not initialised');

                let d : DealPackage | undefined = undefined;
            
                if(getFile){
                    const file = await getFile(x.tokenUri);
                    d = JSON.parse(file);
                }
                else{
                    const file = await this.files.get(x.tokenUri);

                    const decryptedSecret = await this.vault.decrypt(file.owner);
                    const decrypted = decryptBySecret(decryptedSecret, file.deal);
                    d = JSON.parse(decrypted);
                }

                
                const tokenId = BigInt(x.tokenId);
                const payments: SendRequest[] = await this.vault.confidentialDeal.getSendRequestByDeal(tokenId);
                
                const total_locked = (await Promise.all(payments.filter(x=>x.active).map(async element => {
                    const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
                    return BigInt(await this.vault.decrypt(privateAmount));
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                if(!d)
                    throw Error("Deal Not Found");

                return {
                    ...d,
                    key: i + 1,
                    payments: payments,

                    meta: {
                        accepted: Number(x.accepted),
                        cancelled_owner: Number(x.cancelled_owner),
                        cancelled_counterpart: Number(x.cancelled_counterpart),
                        created: Number(x.created),
                        total_locked: BigInt(total_locked)
                    }
                }})
        );
    }
    
    getLiabilities = async (getFile?: (uri: string) => Promise<string>) : Promise<Deal[]> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialDeal)
            throw new Error('Vault is not initialised');

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number, cancelledOwner:number, cancelledCounterpart:number }[] = await this.vault.confidentialDeal.getDealByCounterpart(walletData.address);

        if(_deals.length === 0)
            return [];

        return Promise.all(_deals
            .map((x) => { return { 'tokenId': BigInt(x.tokenId), 'tokenUri': x.tokenUri, 'accepted': x.accepted, 'created': x.created, 'expiry': x.expiry, 'cancelled_owner': x.cancelledOwner, 'cancelled_counterpart': x.cancelledCounterpart } })
            .map(async (x, i) => {
                if(!walletData.address)
                    throw new Error('Vault is not initialised');

                if(!this.vault.confidentialDeal)
                    throw new Error('Vault is not initialised');

                if(!this.vault.confidentialWallet)
                    throw new Error('Wallet is not initialised');

                let d : DealPackage | undefined = undefined;

                if(getFile){
                    const file = await getFile(x.tokenUri);
                    d = JSON.parse(file);
                }
                else{
                    const file = await this.files.get(x.tokenUri);

                    const decryptedSecret = await this.vault.decrypt(file.owner);
                    const decrypted = decryptBySecret(decryptedSecret, file.deal);
                    d = JSON.parse(decrypted);
                }
        
                const tokenId = BigInt(x.tokenId);
                const payments: SendRequest[] = await this.vault.confidentialDeal.getSendRequestByDeal(tokenId);
                
                const total_locked = (await Promise.all(payments.filter(x=>x.active).map(async element => {
                    const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
                    return BigInt(await this.vault.decrypt(privateAmount))
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                if(!d)
                    throw Error("Deal Not Found");
    
                return {
                    ...d,
                    key: -(i + 1),
                    payments: payments,
                    
                    meta: {
                        accepted: Number(x.accepted),
                        cancelled_owner: Number(x.cancelled_owner),
                        cancelled_counterpart: Number(x.cancelled_counterpart),
                        created: Number(x.created),
                        
                        total_locked: total_locked
                    }
                }})
        );
        
    }

    createTx = async (
        pkg: DealPackage,
        getFileId: (data: any) => Promise<string>
    ) : Promise<{idHash: string, safeMintTx: PopulatedTransaction}> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');
        
        let destinationAddress = zeroAddress
        {
            const hashContactId = EthCrypto.hash.keccak256(pkg.deal_address.toLowerCase().trim());
            destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
            if(destinationAddress === zeroAddress)
                destinationAddress = pkg.deal_address;
        }

        let counterpartAddress = zeroAddress
        {
            const hashContactId = EthCrypto.hash.keccak256(pkg.counterpart.toLowerCase().trim());
            counterpartAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
            if(counterpartAddress === zeroAddress)
                counterpartAddress = pkg.deal_address;
        }
    
        let deal : DealPackage = {
            counterpart: pkg.counterpart,
            
            deal_address: destinationAddress === '' ? this.vault.confidentialDeal.address : destinationAddress,
            deal_group_id: pkg.deal_group_id,
            denomination: pkg.denomination,
            obligor: pkg.obligor,
            notional: pkg.notional,
            expiry: pkg.expiry ? pkg.expiry : Math.floor(new Date(2050,1,1).getTime() / 1000),
            data: pkg.data,

            initial_payments: pkg.initial_payments ? await Promise.all(pkg.initial_payments.map(async payment => {
                let oracleOwnerAddress = zeroAddress;
                if(payment.oracle_owner){
                    const oracleOwnerId = EthCrypto.hash.keccak256(payment.oracle_owner.toLowerCase().trim());
                    oracleOwnerAddress = this.vault.db ? await this.vault.db.getAddressByContactId(oracleOwnerId) : await this.vault.confidentialWallet?.getAddressByContactId(oracleOwnerId);
                    if(oracleOwnerAddress === zeroAddress)
                        oracleOwnerAddress = payment.oracle_owner;
                }

                const oracle_address = payment.oracle_address || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);

                const proof_sender = !payment.oracle_key_sender || payment.oracle_key_sender === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_sender, value: payment.oracle_value_sender });
                const proof_recipient = !payment.oracle_key_recipient || payment.oracle_key_recipient === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_recipient, value: payment.oracle_value_recipient });

                return {
                    amount: BigInt(payment.amount ?? 0),
                    oracle_address: oracle_address,
                    oracle_owner: oracleOwnerAddress || zeroAddress,

                    oracle_key_sender: proof_sender.inputs[1],
                    oracle_value_sender: proof_sender.inputs[0],
                    oracle_value_sender_secret: payment.oracle_value_sender || 0,

                    oracle_key_recipient: proof_recipient.inputs[1],
                    oracle_value_recipient: proof_recipient.inputs[0],
                    oracle_value_recipient_secret: payment.oracle_value_recipient || 0,

                    unlock_sender: payment.unlock_sender || 0,
                    unlock_receiver: payment.unlock_receiver || 0
            }})) : []
        }
 
        const cid = await getFileId(deal);
        const expiry = pkg.expiry ?? Math.floor(new Date(2050,1,1).getTime() / 1000);

        const tx = await this.vault.confidentialDeal.populateTransaction.safeMintMeta(walletData.address, counterpartAddress, cid, expiry);
        
        return { idHash: cid, safeMintTx: tx };
    }

    addPaymentsTx = async (
        dealId: BigInt,
        getFile: (data: any) => Promise<string>
    ) : Promise<(PopulatedTransaction | undefined)[]> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');

        let d : DealPackage | undefined = undefined;

        const dealData = await this.vault.confidentialDeal.getDealByID(dealId);

        if(getFile){
            const file = await getFile(dealData.tokenUri);
            d = JSON.parse(file);
        }
        else{
            const file = await this.files.get(dealData.tokenUri);

            const decryptedSecret = await this.vault.decrypt(file.owner);
            const decrypted = decryptBySecret(decryptedSecret, file.deal);
            d = JSON.parse(decrypted);
        }

        if(!d)
            throw new Error('No Deal Found');
        
        const hashContactId = EthCrypto.hash.keccak256(d.deal_address.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = d.deal_address;
    
        const initial_payments = d.initial_payments ? await Promise.all(d.initial_payments.map(async payment => {
                let oracleOwnerAddress = zeroAddress;
                if(payment.oracle_owner){
                    const oracleOwnerId = EthCrypto.hash.keccak256(payment.oracle_owner.toLowerCase().trim());
                    oracleOwnerAddress = this.vault.db ? await this.vault.db.getAddressByContactId(oracleOwnerId) : await this.vault.confidentialWallet?.getAddressByContactId(oracleOwnerId);
                    if(oracleOwnerAddress === zeroAddress)
                        oracleOwnerAddress = payment.oracle_owner;
                }

                const oracle_address = payment.oracle_address || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);

                const proof_sender = !payment.oracle_key_sender || payment.oracle_key_sender === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_sender, value: payment.oracle_value_sender });
                const proof_recipient = !payment.oracle_key_recipient || payment.oracle_key_recipient === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_recipient, value: payment.oracle_value_recipient });

                return {
                    amount: BigInt(payment.amount ?? 0),
                    oracle_address: oracle_address,
                    oracle_owner: oracleOwnerAddress || zeroAddress,

                    oracle_key_sender: proof_sender.inputs[1],
                    oracle_value_sender: proof_sender.inputs[0],
                    oracle_value_sender_secret: payment.oracle_value_sender || 0,

                    oracle_key_recipient: proof_recipient.inputs[1],
                    oracle_value_recipient: proof_recipient.inputs[0],
                    oracle_value_recipient_secret: payment.oracle_value_recipient || 0,

                    unlock_sender: payment.unlock_sender || 0,
                    unlock_receiver: payment.unlock_receiver || 0
            }})) : []

        const deal_group_id = d.deal_group_id;

        const deal_address = destinationAddress === '' ? this.vault.confidentialDeal?.address : destinationAddress;
        const ptxs = initial_payments ? await Promise.all(initial_payments?.map(async payment => {
            const proofSignature = await genProof(this.vault, 'paymentSignature', { 
                denomination: d?.denomination,
                obligor: d?.obligor,
                amount: payment.amount, 
                oracle_address: payment.oracle_address, oracle_owner: payment.oracle_owner, 
    
                oracle_key_sender: payment.oracle_key_sender, oracle_value_sender: payment.oracle_value_sender, 
                oracle_key_recipient: payment.oracle_key_recipient, oracle_value_recipient: payment.oracle_value_recipient, 
                
                unlock_sender: payment.unlock_sender, unlock_receiver: payment.unlock_receiver,
                deal_address: deal_address,
                deal_group_id: deal_group_id,
                deal_id: dealId
            });

            const tx = await this.vault.confidentialDeal?.populateTransaction.addPaymentMeta(walletData.address, dealId, proofSignature.inputs[1]);
            return tx;
        })) : [];
        
        return ptxs;
    }

    acceptTx = async (
        dealId: BigInt, 
        getFile?: (uri: string) => Promise<string>
    ) : Promise<{
        acceptTx: PopulatedTransaction,
        destination: string | undefined,
        afterBalance: string | undefined,
        amounts: { idHash: string, privateAmount_from: string, privateAmount_to: string }[] | undefined
    }> => {
        const walletData = this.vault.getWalletData();

        const groupId = BigInt(0);

        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');

        let d : DealPackage | undefined = undefined;

        const dealData = await this.vault.confidentialDeal.getDealByID(dealId);

        if(getFile){
            const file = await getFile(dealData.tokenUri);
            d = JSON.parse(file);
        }
        else{
            const file = await this.files.get(dealData.tokenUri);

            const decryptedSecret = await this.vault.decrypt(file.owner);
            const decrypted = decryptBySecret(decryptedSecret, file.deal);
            d = JSON.parse(decrypted);
        }

        if(!d)
            throw new Error('No Deal Found');

        const dealGroupId = d.deal_group_id;

        if(d.initial_payments && d.initial_payments?.length > 0){

            let payments : {
                privateAmount_from: string,
                privateAmount_to: string,
                idHash: string,
                data: {
                    denomination: string, 
                    obligor: string,
                
                    oracle_address: string,
                    oracle_owner: string,

                    oracle_key_sender: string | number,
                    oracle_value_sender: string | number,
                    oracle_key_recipient: string | number,
                    oracle_value_recipient: string | number,

                    unlock_sender: number,
                    unlock_receiver: number,
                
                    proof_send: string, 
                    input_send: string[],

                    proof_signature: string, 
                    input_signature: string[]
                }
            }[] = [];
            const beforeBalance = await this.tokens.getBalance(d.denomination, d.obligor);
            let afterBalance = beforeBalance.privateBalance;

            const hashContactId = EthCrypto.hash.keccak256(d.deal_address.toLowerCase().trim());
            let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet?.getAddressByContactId(hashContactId);
            if(destinationAddress === zeroAddress)
                destinationAddress = d.deal_address;

            const owner = await this.vault.confidentialDeal?.ownerOf(dealId);
            const counterPublicKey = this.vault.db ? await this.vault.db.getPublicKey(owner) : await this.vault.confidentialWallet?.getPublicKey(owner);

            let senderNonce = await this.vault.confidentialVault?.getNonce(walletData.address, groupId);
            
            await (async() => {
                if(!d)
                    throw new Error('No Deal Found');

                if(!walletData.publicKey)
                    throw new Error("No public key");

                if(d.initial_payments){
                
                    for (const payment of d.initial_payments){
                        let oracleOwnerAddress = zeroAddress;
                        if(payment.oracle_owner){
                            const oracleOwnerId = EthCrypto.hash.keccak256(payment.oracle_owner.toLowerCase().trim());
                            oracleOwnerAddress = this.vault.db ? await this.vault.db.getAddressByContactId(oracleOwnerId) : await this.vault.confidentialWallet?.getAddressByContactId(oracleOwnerId);
                            if(oracleOwnerAddress === zeroAddress)
                                oracleOwnerAddress = payment.oracle_owner;
                        }

                        const oracle_address = payment.oracle_address || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);

                        const proof_sender = !payment.oracle_key_sender || payment.oracle_key_sender === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_sender, value: payment.oracle_value_sender });
                        const proof_recipient = !payment.oracle_key_recipient || payment.oracle_key_recipient === ''  ? { inputs: [0,0]} : await genProof(this.vault, 'approver', { key: payment.oracle_key_recipient, value: payment.oracle_value_recipient });

                        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: BigInt(afterBalance), amount: BigInt( payment.amount), nonce: BigInt(senderNonce) });

                        afterBalance = BigInt(afterBalance) - BigInt(payment.amount);

                        const deal_address = destinationAddress === '' ? this.vault.confidentialDeal?.address : destinationAddress;

                        const deal_group_id = dealGroupId;
                       
                        const proofSignature = await genProof(this.vault, 'paymentSignature', { 
                            denomination: d.denomination,
                            obligor: d.obligor,
                            amount: payment.amount, 
                            oracle_address: oracle_address,
                            oracle_owner: oracleOwnerAddress || zeroAddress,
                
                            oracle_key_sender: proof_sender.inputs[1],
                            oracle_value_sender: proof_sender.inputs[0],

                            oracle_key_recipient: proof_recipient.inputs[1],
                            oracle_value_recipient: proof_recipient.inputs[0],
                            
                            unlock_sender: payment.unlock_sender || 0,
                            unlock_receiver: payment.unlock_receiver || 0,

                            deal_address: deal_address,
                            deal_group_id: deal_group_id,
                            deal_id: dealId
                        });

                        senderNonce++;
                        
                        const privateAmount_from = await encrypt(walletData.publicKey, payment.amount);
                        const privateAmount_to = await encrypt(counterPublicKey, payment.amount);

                        payments.push({
                            privateAmount_from: privateAmount_from,
                            privateAmount_to: privateAmount_to,
                            idHash: proofSignature.inputs[1],
                            data: {
                                // recipient: destinationAddress, 
                                denomination: d?.denomination, 
                                obligor: d?.obligor,
                            
                                oracle_address: oracle_address,
                                oracle_owner: oracleOwnerAddress || zeroAddress,

                                oracle_key_sender: proof_sender.inputs[1],
                                oracle_value_sender: proof_sender.inputs[0],

                                oracle_key_recipient: proof_recipient.inputs[1],
                                oracle_value_recipient: proof_recipient.inputs[0],
                                
                                unlock_sender: payment.unlock_sender || 0,
                                unlock_receiver: payment.unlock_receiver || 0,
                            
                                proof_send: proofSend.solidityProof, 
                                input_send: proofSend.inputs,

                                proof_signature: proofSignature.solidityProof, 
                                input_signature: proofSignature.inputs
                            }
                        });
                    }
                }
            })();

            const ps = payments.map(x=>x.data);

            const tx = await this.vault.confidentialVault
                .populateTransaction
                .createRequestMeta(walletData.address, groupId, ps, this.vault.confidentialDeal.address, dealGroupId, dealId, true);

            return { acceptTx: tx, destination: owner, afterBalance: await encrypt(walletData.publicKey, afterBalance), amounts: payments.map(x=> { return { privateAmount_from: x.privateAmount_from, privateAmount_to:x.privateAmount_to, idHash:x.idHash } }) };
        }
        else{
            const tx =  await this.vault.confidentialDeal.populateTransaction.acceptMeta(walletData.address, dealId);

            return { acceptTx: tx, destination: undefined, afterBalance: undefined, amounts: undefined };
        }
    }

    approveTx = async (key: string, value: string) : Promise<string> =>  {
        if(!(this.vault.confidentialOracle && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const proof = await genProof(this.vault, 'approver', { key: key, value: value});

        const tx = await this.vault.confidentialOracle.setValueTx(proof.solidityProof, proof.inputs);
        return (await this.vault.signTx(tx)).signature;
    }
}