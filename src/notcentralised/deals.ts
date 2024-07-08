/* 
 SPDX-License-Identifier: MIT
 Deals SDK for Typescript v0.9.0 (deals.ts)

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

import { PopulatedTransaction } from 'ethers';

import * as EthCrypto from "eth-crypto";

import { Tokens, SendRequest, zeroAddress } from './tokens';
import { NotVault, hederaList } from './notvault';
import { genProof } from './proof';

import { v4 as uuidv4 } from 'uuid';

export type DealPackage = {
    owner: string,
    counterpart: string,

    denomination: string,
    obligor: string,

    notional: bigint,
    expiry: number
    
    data: any,
    initial_payments?: {
        amount: bigint,

        oracle_address: string,
        oracle_owner: string,

        oracle_key_sender: string | number,
        oracle_value_sender: string | number,
        oracle_value_sender_secret: string | number,

        oracle_key_recipient: string | number,
        oracle_value_recipient: string | number,
        oracle_value_recipient_secret: string | number,

        unlock_sender: number,
        unlock_receiver: number,
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
            const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(element.sender, this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
            return BigInt(await this.vault.decrypt(privateAmount));
        }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

        // eslint-disable-next-line
        // const { balance, decimals } = await this.tokens.tokenBalance(d.denomination);

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
                total_locked: BigInt(total_locked) // decimals
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
                    const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(element.sender, this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
                    return BigInt(await this.vault.decrypt(privateAmount));
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                // eslint-disable-next-line
                // const { balance, decimals } = await this.tokens.tokenBalance(d.denomination);

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
                        total_locked: BigInt(total_locked) // decimals
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
                    const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(element.sender, this.vault.confidentialVault?.address ?? '', this.vault.getWalletData().address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, this.vault.getWalletData().address, element.idHash);
                    return BigInt(await this.vault.decrypt(privateAmount))
                }))).reduce((acc, val) => BigInt(acc) + BigInt(val), BigInt(0));

                // eslint-disable-next-line
                // const { balance, decimals } = await this.tokens.tokenBalance(d.denomination);
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
                        
                        total_locked: total_locked // decimals
                    }
                }})
        );
        
    }
    
    create = async (pkg: DealPackage) : Promise<string> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');
        
        const hashContactId = EthCrypto.hash.keccak256(pkg.counterpart.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = pkg.counterpart;

        let deal : DealPackage = {
            owner: walletData.address,
            counterpart: destinationAddress,
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
    
        let dealPackage = JSON.stringify(deal);
    
        const counterPublicKey = this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet.getPublicKey(destinationAddress);
    
        const secret = uuidv4();
        const encryptedDealBySecret = encryptedBySecret(secret, dealPackage);
    
        const ownerEncryptedSecret = await encrypt(walletData.publicKey, secret);
        const counterEncryptedSecret = await encrypt(counterPublicKey, secret);
    
        const encryptedDeal = JSON.stringify({ owner: ownerEncryptedSecret, counterpart: counterEncryptedSecret, deal: encryptedDealBySecret }); 

        const cid = await this.files.set('deal.json', encryptedDeal);
    
        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialDeal.safeMint(destinationAddress, cid, pkg.expiry, { gasLimit: BigInt(325_000/*303_191*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialDeal.safeMint(destinationAddress, cid, pkg.expiry);
            await tx.wait();
        }
    
        return cid;
    }

    createTx = async (
        pkg: DealPackage,
        getFileId: (data: any) => Promise<string>
    ) : Promise<{idHash: string, safeMintTx: PopulatedTransaction}> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');
        
        const hashContactId = EthCrypto.hash.keccak256(pkg.counterpart.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = pkg.counterpart;
    
        let deal : DealPackage = {
            owner: walletData.address,
            counterpart: destinationAddress,
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

        const tx = await this.vault.confidentialDeal.populateTransaction.safeMintMeta(walletData.address, destinationAddress, cid, expiry);
        
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
        
        const hashContactId = EthCrypto.hash.keccak256(d.counterpart.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = d.counterpart;
    
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

    
        const ptxs = initial_payments ? await Promise.all(initial_payments?.map(async payment => {
            const proofSignature = await genProof(this.vault, 'paymentSignature', { 
                denomination: d?.denomination,
                obligor: d?.obligor,
                amount: payment.amount, 
                oracle_address: payment.oracle_address, oracle_owner: payment.oracle_owner, 
    
                oracle_key_sender: payment.oracle_key_sender, oracle_value_sender: payment.oracle_value_sender, 
                oracle_key_recipient: payment.oracle_key_recipient, oracle_value_recipient: payment.oracle_value_recipient, 
                
                unlock_sender: payment.unlock_sender, unlock_receiver: payment.unlock_receiver,
                deal_id: dealId
            });

            const tx = await this.vault.confidentialDeal?.populateTransaction.addPaymentMeta(walletData.address, dealId, proofSignature.inputs[1]);
            return tx;
        })) : [];
        
        return ptxs;
    }

    accept = async (
        dealId: BigInt, 
        getFile?: (uri: string) => Promise<string>
    ) : Promise<void> => {

        const walletData = this.vault.getWalletData();

        if(!(this.vault.confidentialDeal && this.vault.chainId && walletData.address && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');


        let d : DealPackage | undefined = undefined

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

            if(d.initial_payments && d.initial_payments?.length > 0){

                let payments : {
                    privateAmount_from: string,
                    privateAmount_to: string,
                    idHash: string,
                    data: {
                        recipient: string, 
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
    
                const hashContactId = EthCrypto.hash.keccak256(d.counterpart.toLowerCase().trim());
                let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet?.getAddressByContactId(hashContactId);
                if(destinationAddress === zeroAddress)
                    destinationAddress = d.counterpart;
    
                const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet?.getPublicKey(destinationAddress);
    
                let senderNonce = await this.vault.confidentialVault?.getNonce(walletData.address);
                
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
                                recipient: destinationAddress, 
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
    
    
                }})();
    
                const ps = payments.map(x=>x.data);
    
                const tx = await this.vault.confidentialVault
                    .createRequest(ps, this.vault.confidentialDeal.address, dealId, true);
                await tx.wait();
    
                // return { acceptTx: tx, destination: destinationAddress, afterBalance: await encrypt(walletData.publicKey, afterBalance), amounts: payments.map(x=> { return { privateAmount_from: x.privateAmount_from, privateAmount_to:x.privateAmount_to, idHash:x.idHash } }) };
            }
            else{
                const tx =  await this.vault.confidentialDeal.accept(dealId);
                await tx.wait();
            }
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

        if(d.initial_payments && d.initial_payments?.length > 0){

            let payments : {
                privateAmount_from: string,
                privateAmount_to: string,
                idHash: string,
                data: {
                    recipient: string, 
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

            const hashContactId = EthCrypto.hash.keccak256(d.counterpart.toLowerCase().trim());
            let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet?.getAddressByContactId(hashContactId);
            if(destinationAddress === zeroAddress)
                destinationAddress = d.counterpart;

            const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet?.getPublicKey(destinationAddress);

            let senderNonce = await this.vault.confidentialVault?.getNonce(walletData.address);
            
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
                            recipient: destinationAddress, 
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


            }})();

            const ps = payments.map(x=>x.data);

            const tx = await this.vault.confidentialVault
                .populateTransaction
                .createRequestMeta(walletData.address, ps, this.vault.confidentialDeal.address, dealId, true);

            return { acceptTx: tx, destination: destinationAddress, afterBalance: await encrypt(walletData.publicKey, afterBalance), amounts: payments.map(x=> { return { privateAmount_from: x.privateAmount_from, privateAmount_to:x.privateAmount_to, idHash:x.idHash } }) };
        }
        else{
            const tx =  await this.vault.confidentialDeal.populateTransaction.acceptMeta(walletData.address, dealId);

            return { acceptTx: tx, destination: undefined, afterBalance: undefined, amounts: undefined };
        }
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

    approveTx = async (key: string, value: string) : Promise<string> =>  {
        if(!(this.vault.confidentialOracle && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const proof = await genProof(this.vault, 'approver', { key: key, value: value});

        const tx = await this.vault.confidentialOracle.setValueTx(proof.solidityProof, proof.inputs);
        return await this.vault.signTx(tx);
    }
}