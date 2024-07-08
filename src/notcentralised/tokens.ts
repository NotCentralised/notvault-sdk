
/* 
 SPDX-License-Identifier: MIT
 Tokens SDK for Typescript v0.9.0 (tokens.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { NotVault, hederaList } from './notvault';

import * as EthCrypto from "eth-crypto";

import { Contract, PopulatedTransaction } from 'ethers';
import ConfidentialTreasury from './abi/ConfidentialTreasury.json';

import { encrypt } from './encryption';
import { genProof } from './proof';

import { DealStruct} from './deals';

export type SendRequest = {
    idHash: bigint,
    sender: string,
    recipient: string,
    amount: bigint,
    created: number,
    unlock_sender: number,
    unlock_receiver: number,
    redeemed: number,
    active: boolean,

    amount_hash: bigint,
    
    deal_address: string,
    deal_id: bigint,
    denomination: string,
    obligor: string,
    oracle_address: string,
    oracle_owner: string,
    oracle_key_sender: bigint,
    oracle_value_sender: bigint
    oracle_key_recipient: bigint,
    oracle_value_recipient: bigint
}

export type Balance = { 
    privateBalance: bigint, 
    lockedOut: SendRequest[], 
    lockedIn: SendRequest[], 
    balance: bigint, 
    decimals: bigint 
}

export const zeroAddress = '0x0000000000000000000000000000000000000000';

export class Tokens
{
    vault: NotVault;
    constructor(vault: NotVault){
        this.vault = vault;
    }

    _encryptedBalance = '';
    _decryptedBalance = BigInt(0);
    _lockedIn: SendRequest[] = [];
    _lockedOut: SendRequest[] = [];

    getBalance = async (denomination: string, obligor: string) : Promise<Balance> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.privateBalanceOf){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }

        if(!this.vault.confidentialDeal)
            throw new Error('Deal is not initialised');


        const privateBalance = this.vault.db?.privateBalanceOf ? await this.vault.db?.privateBalanceOf(walletData.address, this.vault.confidentialVault.address, denomination, obligor) : await this.vault.confidentialWallet?.privateBalanceOf(this.vault.confidentialVault.address, walletData.address, denomination);
        
        if (this._encryptedBalance !== privateBalance) {
            this._encryptedBalance = privateBalance;
            
            this._decryptedBalance = this._encryptedBalance === '' ? BigInt(0) : (BigInt(await this.vault.decrypt(privateBalance)));

            const __lockedOut = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, obligor, true);
            
            if(__lockedOut.length > 0){
            
                this._lockedOut = await Promise.all(__lockedOut.filter((element: any) => element.denomination === denomination).map(async (element: any) => {
                    const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(element.sender, this.vault.confidentialVault?.address ?? '', walletData.address ?? '', element.idHash.toString()) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
                    const _amount = await this.vault.decrypt(__amount);
                    return {
                        idHash: element.idHash,
                        sender: element.sender,
                        recipient: element.recipient,
                        amount: BigInt(_amount),
                        created: Number(element.created),
                        unlock_sender: Number(element.unlock_sender),
                        unlock_receiver: Number(element.unlock_receiver),
                        redeemed: Number(element.redeemed),
                        active: element.active,

                        amount_hash: BigInt(element.amount_hash),
                        
                        deal_address: element.deal_address,
                        deal_id: BigInt(element.deal_id),
                        denomination: element.denomination,
                        obligor: element.obligor,

                        oracle_address: element.oracle_address,
                        oracle_owner: element.oracle_owner,

                        oracle_key_sender: BigInt(element.oracle_key_sender),
                        oracle_value_sender: BigInt(element.oracle_value_sender),
                        oracle_key_recipient: BigInt(element.oracle_key_recipient),
                        oracle_value_recipient: BigInt(element.oracle_value_recipient)
                    }
                }));      
            }            
        }

        let __lockedIn : SendRequest[] = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, obligor, false);

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
        const _dealLock = await Promise.all(_deals.map(async deal => {
            return await this.vault.confidentialVault?.getSendRequestByAddress(this.vault.confidentialDeal?.address, deal.tokenId, false);
        }));

        __lockedIn = __lockedIn.concat(_dealLock.flat())

        if(__lockedIn.length > 0)
            this._lockedIn = await Promise.all(__lockedIn.filter((element: any) => element.denomination === denomination).map(async element => {
                const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(element.sender, this.vault.confidentialVault?.address ?? '', walletData.address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
                const _amount = await this.vault.decrypt(__amount);
                return {
                    idHash: element.idHash,
                    sender: element.sender,
                    recipient: element.recipient,
                    amount: BigInt(_amount),
                    created: Number(element.created),
                    unlock_sender: Number(element.unlock_sender),
                    unlock_receiver: Number(element.unlock_receiver),
                    redeemed: Number(element.redeemed),
                    active: element.active,

                    amount_hash: BigInt(element.amount_hash),

                    deal_address: element.deal_address,
                    deal_id: BigInt(element.deal_id),
                    denomination: element.denomination,
                    obligor: element.obligor,
                    
                    oracle_address: element.oracle_address,
                    oracle_owner: element.oracle_owner,

                    oracle_key_sender: BigInt(element.oracle_key_sender),
                    oracle_value_sender: BigInt(element.oracle_value_sender),
                    oracle_key_recipient: BigInt(element.oracle_key_recipient),
                    oracle_value_recipient: BigInt(element.oracle_value_recipient)
                }
            }));        
        const { balance, decimals } = await this.tokenBalance(denomination);

        return { privateBalance: this._decryptedBalance, lockedOut: this._lockedOut, lockedIn: this._lockedIn, balance: balance, decimals: decimals };
    }

    private tokenDecimalCache : { [key: string]: string } = {};
    tokenBalance = async (denomination: string) : Promise<{ balance: bigint, decimals: bigint }> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        const tokenProxy = new Contract(denomination, ConfidentialTreasury.abi, this.vault.signer);
        const tokenBalance: BigInt = BigInt(await tokenProxy.balanceOf(walletData.address));

        if (!(denomination in this.tokenDecimalCache)){
            const DEC: string = await tokenProxy.decimals();
            this.tokenDecimalCache[denomination] = DEC;
        }
        
        return { balance: tokenBalance.valueOf(), decimals: BigInt(10 ** Number(this.tokenDecimalCache[denomination])).valueOf()};
    }

    deposit = async (denomination: string, obligor: string, amount: bigint) : Promise<void> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialWallet)
            throw new Error('Wallet is not initialised');

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tokenProxy = new Contract(denomination, ConfidentialTreasury.abi, this.vault.signer);
        if(hederaList.includes(this.vault.chainId)){
            const tx = await tokenProxy.approve(this.vault.confidentialVault.address, amount, { gasLimit: BigInt(50_000/*46_923*/) });
            await tx.wait();
        }
        else{
            const tx = await tokenProxy.approve(this.vault.confidentialVault.address, amount);
            await tx.wait();
        }

        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault.deposit(denomination, obligor, amount, proofReceive.solidityProof, proofReceive.inputs, { gasLimit: BigInt(600_000/*552_191*/) });
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance) : await this.vault.confidentialWallet.setPrivateBalance(this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        else{
            const tx1 = await this.vault.confidentialVault.deposit(denomination, obligor, amount, proofReceive.solidityProof, proofReceive.inputs);
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance) : await this.vault.confidentialWallet.setPrivateBalance(this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
    }

    depositTx = async (denomination: string, obligor: string, amount: bigint) : Promise<{approveTx: PopulatedTransaction, depositTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tokenProxy = new Contract(denomination, ConfidentialTreasury.abi, this.vault.signer);
        const tx = await tokenProxy.populateTransaction.approveMeta(walletData.address, this.vault.confidentialVault.address, amount);
        
        const tx1 = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, denomination, obligor, amount, proofReceive.solidityProof, proofReceive.inputs);
        
        return {
            approveTx: tx,
            depositTx: tx1,
            privateAfterBalance: privateAfterBalance
         }
    }

    depositUnfundedTx = async (denomination: string, obligor: string, amount: bigint) : Promise<{depositTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tx1 = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, denomination, obligor, 0, proofReceive.solidityProof, proofReceive.inputs);
        
        return {
            // approveTx: tx,
            depositTx: tx1,
            privateAfterBalance: privateAfterBalance
         }
    }

    withdraw = async (denomination:string, obligor: string, amount: bigint) : Promise<string> => {
        
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination, obligor);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });

        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault.withdraw(denomination, obligor, amount, proofSend.solidityProof, proofSend.inputs, { gasLimit: BigInt(400_000/*374_927*/) });
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance) : await this.vault.confidentialWallet?.setPrivateBalance(this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        else{
            const tx1 = await this.vault.confidentialVault.withdraw(walletData.address, denomination, obligor, amount, proofSend.solidityProof, proofSend.inputs);
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance) : await this.vault.confidentialWallet?.setPrivateBalance(this.vault.confidentialVault.address, denomination, obligor, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        
        return proofSend.inputs[4];
    }

    withdrawTx = async (denomination:string, obligor: string, amount: bigint) : Promise<{idHash: string, withdrawTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination, obligor);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });

        const tx1 = await this.vault.confidentialVault.populateTransaction.withdrawMeta(walletData.address, denomination, obligor, amount, proofSend.solidityProof, proofSend.inputs);
        
        return {
            idHash: proofSend.inputs[4],
            withdrawTx: tx1,
            privateAfterBalance: privateAfterBalance,
        };
    }

    send = async (
            denomination: string, 
            obligor: string,

            destination: string, 
            
            amount: bigint, 
            oracleAddress?: string, 
            oracleOwner?: string, 

            oracleKeySender?: number | string, 
            oracleValueSender?: number | string, 
            oracleKeyRecipient?: number | string, 
            oracleValueRecipient?: number | string, 

            unlockSender?: number, 
            unlockReceiver?:number,
            dealId?: BigInt
        ) : Promise<string> => {
        
            const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault && this.vault.confidentialDeal && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const hashContactId = EthCrypto.hash.keccak256(destination.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = destination;

        const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet.getPublicKey(destinationAddress);

        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
    
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { 
            sender: walletData.address, 
            senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), 
            amount: BigInt(amount), 
            nonce: BigInt(senderNonce) 
        });
        
        let proofApproveSender;
        if(oracleKeySender && oracleValueSender)
            proofApproveSender = await genProof(this.vault, 'approver', { key: oracleKeySender, value: oracleValueSender});

        let proofApproveRecipient;
        if(oracleKeyRecipient && oracleValueRecipient)
            proofApproveRecipient = await genProof(this.vault, 'approver', { key: oracleKeyRecipient, value: oracleValueRecipient});


        const deal_address = this.vault.confidentialDeal.address;
        const deal_id = dealId || BigInt(0);
        const oracle_address = oracleAddress || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);
        const oracle_owner = oracleOwner || zeroAddress;

        const oracle_key_sender = oracleKeySender || 0;
        const oracle_value_sender = oracleValueSender || 0;
        const oracle_key_recipient = oracleKeyRecipient || 0;
        const oracle_value_recipient = oracleValueRecipient || 0;

        const unlock_sender = unlockSender || 0;
        const unlock_receiver = unlockReceiver || 0;

        const proofSignature = await genProof(this.vault, 'paymentSignature', { 
            denomination: denomination,
            amount: amount, 
            obligor: obligor,
            oracle_address: oracle_address, oracle_owner: oracle_owner, 

            oracle_key_sender: oracle_key_sender, oracle_value_sender: oracle_value_sender, 
            oracle_key_recipient: oracle_key_recipient, oracle_value_recipient: oracle_value_recipient, 
            
            unlock_sender: unlock_sender, unlock_receiver: unlock_receiver,
            deal_id: dealId ?? BigInt(0)
        });
    
        const idHash = proofSignature.inputs[1];
        
        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault
                .createRequest([{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                    obligor: obligor,
                
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    proof_send: proofSend.solidityProof, 
                    input_send: proofSend.inputs,

                    proof_signature: proofSignature.solidityProof, 
                    input_signature: proofSignature.inputs
                }], deal_address, deal_id, false, { gasLimit: BigInt(1_200_000/*1_152_414*/) });
            
            await tx1.wait();

            const tx2 = this.vault.db ? 
                await this.vault.db.setPrivateBalance(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    privateAfterBalance
                ) 
                : 
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    privateAfterBalance
                );

            if(tx2.wait)
                await tx2.wait();

            const tx3 = this.vault.db ? 
                await this.vault.db.setPrivateAmount(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    walletData.address,
                    idHash,
                    privateAmount_from
                )
                :
                await this.vault.confidentialWallet.setPrivateAmount(
                    this.vault.confidentialVault.address,
                    walletData.address,
                    idHash,
                    privateAmount_from
                );

            if(tx3.wait)
                await tx3.wait();

            const tx4 = this.vault.db ? 
                await this.vault.db.setPrivateAmount(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    destinationAddress,
                    idHash,
                    privateAmount_to
                )
                :
                await this.vault.confidentialWallet.setPrivateAmount(
                    this.vault.confidentialVault.address,
                    destinationAddress,
                    idHash,
                    privateAmount_to
                );

            if(tx4.wait)
                await tx4.wait();
        }
        else {
            const tx1 = await this.vault.confidentialVault
                .createRequest([{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                    obligor: obligor,
                
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    proof_send: proofSend.solidityProof, 
                    input_send: proofSend.inputs,

                    proof_signature: proofSignature.solidityProof, 
                    input_signature: proofSignature.inputs

                    }], deal_address, deal_id, false);
            
            await tx1.wait();

            const tx2 = this.vault.db ? 
                await this.vault.db.setPrivateBalance(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    privateAfterBalance
                ) 
                : 
                await this.vault.confidentialWallet
                    .setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    privateAfterBalance
                );

            if(tx2.wait)
                await tx2.wait();

            const tx3 = this.vault.db ? 
                await this.vault.db.setPrivateAmount(
                    this.vault.getWalletData().address ?? '',
                    this.vault.confidentialVault.address,
                    this.vault.getWalletData().address ?? '',
                    idHash,
                    privateAmount_from
                )
                :
                await this.vault.confidentialWallet.setPrivateAmount(
                    this.vault.confidentialVault.address,
                    this.vault.getWalletData().address,
                    idHash,
                    privateAmount_from
                );

            if(tx3.wait)
                await tx3.wait();

            const tx4 = this.vault.db ? 
                await this.vault.db.setPrivateAmount(
                    this.vault.getWalletData().address ?? '',
                    this.vault.confidentialVault.address,
                    destinationAddress,
                    idHash,
                    privateAmount_to
                )
                :
                await this.vault.confidentialWallet.setPrivateAmount(
                    this.vault.confidentialVault.address,
                    destinationAddress,
                    idHash,
                    privateAmount_to
                );

            if(tx4.wait)
                await tx4.wait();
        }
        return idHash;
    }

    sendTx = async (
        denomination: string, 
        obligor: string,
        
        destination: string, 
        
        amount: bigint, 
        oracleAddress?: string, 
        oracleOwner?: string, 

        oracleKeySender?: number | string, 
        oracleValueSender?: number | string, 
        oracleKeyRecipient?: number | string, 
        oracleValueRecipient?: number | string, 

        unlockSender?: number, 
        unlockReceiver?:number,
        dealId?: BigInt
    ) : Promise<{
        idHash: string, 
        createRequestTx: PopulatedTransaction, 
        privateAfterBalance: string, 
        privateAfterAmount_from: string, 
        privateAfterAmount_to: string
    }> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault && this.vault.confidentialDeal && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const hashContactId = EthCrypto.hash.keccak256(destination.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = destination;

        const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet.getPublicKey(destinationAddress);

        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);

        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), amount: BigInt(amount), nonce: BigInt(senderNonce) });
        
        let proofApproveSender;
        if(oracleKeySender && oracleValueSender)
            proofApproveSender = await genProof(this.vault, 'approver', { key: oracleKeySender, value: oracleValueSender });

        let proofApproveRecipient;
        if(oracleKeyRecipient && oracleValueRecipient)
            proofApproveRecipient = await genProof(this.vault, 'approver', { key: oracleKeyRecipient, value: oracleValueRecipient});


        const deal_address = this.vault.confidentialDeal.address;
        const deal_id = dealId || BigInt(0);
        const oracle_address = oracleAddress || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);
        const oracle_owner = oracleOwner || zeroAddress;

        const oracle_key_sender = oracleKeySender || 0;
        const oracle_value_sender = oracleValueSender || 0;
        const oracle_key_recipient = oracleKeyRecipient || 0;
        const oracle_value_recipient = oracleValueRecipient || 0;

        const unlock_sender = unlockSender || 0;
        const unlock_receiver = unlockReceiver || 0;

        const dealStruct: DealStruct = dealId ? await this.vault.confidentialDeal.getDealByID(deal_id) : undefined;

        const proofSignature = await genProof(this.vault, 'paymentSignature', { 
            denomination: denomination,
            obligor: obligor,
            amount: amount, 
            oracle_address: oracle_address, oracle_owner: oracle_owner, 

            oracle_key_sender: oracle_key_sender, oracle_value_sender: oracle_value_sender, 
            oracle_key_recipient: oracle_key_recipient, oracle_value_recipient: oracle_value_recipient, 
            
            unlock_sender: unlock_sender, unlock_receiver: unlock_receiver,
            deal_id: dealId ?? BigInt(0)
        });

        const idHash = proofSignature.inputs[1];
            
        const tx1 = await this.vault.confidentialVault
            .populateTransaction
            .createRequestMeta(walletData.address, [{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                    obligor: obligor,
                
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    proof_send: proofSend.solidityProof, 
                    input_send: proofSend.inputs,

                    proof_signature: proofSignature.solidityProof, 
                    input_signature: proofSignature.inputs
                }], deal_address, deal_id, false);
        
        return {
            idHash: idHash, 
            createRequestTx: tx1, 
            privateAfterBalance: privateAfterBalance, 
            privateAfterAmount_from: privateAmount_from, 
            privateAfterAmount_to: privateAmount_to
        };
    }
    
    retreive = async (idHash: string, denomination: string, obligor: string) => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        const beforeBalance = await this.getBalance(denomination, obligor);

        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);
    
        const amount = BigInt(await this.vault.decrypt(privateAmount));
    
        const afterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);
    
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault.acceptRequest(idHash, proofReceive.solidityProof, proofReceive.inputs, { gasLimit: BigInt(650_000/*618_821*/) });
            await tx1.wait();

            const tx2 = 
                this.vault.db ?
                await this.vault.db.setPrivateBalance(
                    walletData.address, 
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    afterBalance
                )
                :
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    afterBalance
                );

            if(tx2.wait)
                await tx2.wait();
        }
        else{
            const tx1 = await this.vault.confidentialVault.acceptRequest(idHash, proofReceive.solidityProof, proofReceive.inputs);
            await tx1.wait();

            const tx2 = 
                this.vault.db ?
                await this.vault.db.setPrivateBalance(
                    walletData.address, 
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    afterBalance
                )
                :
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    obligor,
                    afterBalance
                );

            if(tx2.wait)
                await tx2.wait();
        }
    }

    retreiveTx = async (idHash: string, denomination: string, obligor: string) : Promise<{acceptRequestTx: PopulatedTransaction, privateAfterBalance: string}> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        const beforeBalance = await this.getBalance(denomination, obligor);

        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);
    
        const amount = BigInt(await this.vault.decrypt(privateAmount));

        const afterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);

        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const tx1 = await this.vault.confidentialVault.populateTransaction.acceptRequestMeta(walletData.address, idHash, proofReceive.solidityProof, proofReceive.inputs);
        
        return {
            acceptRequestTx: tx1,
            privateAfterBalance: afterBalance
        }
    }
}