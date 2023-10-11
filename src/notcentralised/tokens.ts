
/* 
 SPDX-License-Identifier: MIT
 Tokens SDK for Typescript v0.5.3 (tokens.ts)

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

import { Contract } from 'ethers';
import ProxyToken from './abi/ProxyToken.json';

import { encrypt } from './encryption';
import { genProof } from './proof';

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
    private_sender_amount: string,
    private_receiver_amount: string,
    
    deal_address: string,
    deal_id: bigint,
    denomination: string,
    oracle_address: string,
    oracle_owner: string,
    oracle_key: bigint,
    oracle_value: bigint
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

    getBalance = async (denomination: string) : Promise<Balance> => {
        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');


        const privateBalance = await this.vault.confidentialVault.privateBalanceOf(walletData.address, denomination);


        if (this._encryptedBalance !== privateBalance) {
            this._encryptedBalance = privateBalance;
            this._decryptedBalance = this._encryptedBalance === '' ? BigInt(0) : (BigInt(await this.vault.decrypt(privateBalance)));

            const __lockedOut = await this.vault.confidentialVault.getSendRequestBySender(walletData.address);

            if(__lockedOut.length > 0){
            
                this._lockedOut = await Promise.all(__lockedOut.filter((element: any) => element.denomination === denomination).map(async (element: any) => {

                    return {
                        idHash: BigInt(element.idHash),
                        sender: element.sender,
                        recipient: element.recipient,
                        amount: BigInt(await this.vault.decrypt(element.private_sender_amount)),
                        created: Number(element.created),
                        unlock_sender: Number(element.unlock_sender),
                        unlock_receiver: Number(element.unlock_receiver),
                        redeemed: Number(element.redeemed),
                        active: element.active,

                        amount_hash: BigInt(element.amount_hash),
                        private_sender_amount: element.private_sender_amount,
                        private_receiver_amount: element.private_receiver_amount,

                        deal_address: element.deal_address,
                        deal_id: BigInt(element.deal_id),
                        denomination: element.denomination,
                        oracle_address: element.oracle_address,
                        oracle_owner: element.oracle_owner,
                        oracle_key: BigInt(element.oracle_key),
                        oracle_value: BigInt(element.oracle_value)
                    }
                }));      
            } 
        }

        const __lockedIn : SendRequest[] = await this.vault.confidentialVault.getSendRequestByReceiver(walletData.address);
        if(__lockedIn.length > 0)
            this._lockedIn = await Promise.all(__lockedIn.filter((element: any) => element.denomination === denomination).map(async element => {
                return {
                    idHash: BigInt(element.idHash),
                    sender: element.sender,
                    recipient: element.recipient,
                    amount: BigInt(await this.vault.decrypt(element.private_receiver_amount)),
                    created: Number(element.created),
                    unlock_sender: Number(element.unlock_sender),
                    unlock_receiver: Number(element.unlock_receiver),
                    redeemed: Number(element.redeemed),
                    active: element.active,

                    amount_hash: BigInt(element.amount_hash),
                    private_sender_amount: element.private_sender_amount,
                    private_receiver_amount: element.private_receiver_amount,

                    deal_address: element.deal_address,
                    deal_id: BigInt(element.deal_id),
                    denomination: element.denomination,
                    oracle_address: element.oracle_address,
                    oracle_owner: element.oracle_owner,
                    oracle_key: BigInt(element.oracle_key),
                    oracle_value: BigInt(element.oracle_value)
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

        const tokenProxy = new Contract(denomination, ProxyToken.abi, this.vault.signer);
        const tokenBalance: BigInt = BigInt(await tokenProxy.balanceOf(walletData.address));

        if (!(denomination in this.tokenDecimalCache)){
            const DEC: string = await tokenProxy.decimals();
            this.tokenDecimalCache[denomination] = DEC;
        }
        
        return { balance: tokenBalance.valueOf(), decimals: BigInt(10 ** Number(this.tokenDecimalCache[denomination])).valueOf()};
    }

    deposit = async (denomination: string, amount: bigint) : Promise<void> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

            if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');


        const beforeBalance = await this.getBalance(denomination);

        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const tokenProxy = new Contract(denomination, ProxyToken.abi, this.vault.signer);
        if(hederaList.includes(this.vault.chainId)){
            const tx = await tokenProxy.approve(this.vault.confidentialVault.address, amount, { gasLimit: BigInt(50_000/*46_923*/) });
            await tx.wait();
        }
        else{
            const tx = await tokenProxy.approve(this.vault.confidentialVault.address, amount);
            await tx.wait();
        }

        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialVault.deposit(denomination, amount, privateAfterBalance, proofReceive.solidityProof, proofReceive.inputs, { gasLimit: BigInt(600_000/*552_191*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialVault.deposit(denomination, amount, privateAfterBalance, proofReceive.solidityProof, proofReceive.inputs);
            await tx.wait();
        }
    }

    withdraw = async (denomination:string, amount: bigint) : Promise<string> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');


        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });

        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialVault.withdraw(denomination, amount, privateAfterBalance, proofSend.solidityProof, proofSend.inputs, { gasLimit: BigInt(400_000/*374_927*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialVault.withdraw(denomination, amount, privateAfterBalance, proofSend.solidityProof, proofSend.inputs);
            await tx.wait();
        }
        
        return proofSend.inputs[4];
    }

    send = async (
            denomination: string, 
            destination: string, 
            amount: bigint, 
            dealId?: BigInt, 
            oracleAddress?: string, 
            oracleOwner?: string, 
            oracleKey?: number, 
            oracleValue?: number, 
            unlockSender?: number, 
            unlockReceiver?:number
        ) : Promise<string> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault && this.vault.confidentialDeal && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const hashContactId = EthCrypto.hash.keccak256(destination.toLowerCase().trim());
        let destinationAddress = await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = destination;

        const counterPublicKey = await this.vault.confidentialWallet.getPublicKey(destinationAddress);

        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
    
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), amount: BigInt(amount), nonce: BigInt(senderNonce) });
        let proofApprove;
        if(oracleKey && oracleValue)
            proofApprove = await genProof(this.vault, 'approver', { key: oracleKey, value: oracleValue});


        const deal_address = this.vault.confidentialDeal.address;
        const deal_id = dealId || BigInt(0);
        const oracle_address = oracleAddress || (this.vault.confidentialOracle ? this.vault.confidentialOracle.address : zeroAddress);
        const oracle_owner = oracleOwner || zeroAddress;
        const oracle_key = oracleKey || 0;
        const oracle_value = oracleValue || 0;
        const unlock_sender = unlockSender || 0;
        const unlock_receiver = unlockReceiver || 0;

        const proofAgree = await genProof(this.vault, 'minCommitment', { amount: amount, minAmount: amount, oracle_owner: oracle_owner, oracle_key: oracle_key, oracle_value: oracle_value, unlock_sender: unlock_sender, unlock_receiver: unlock_receiver });
    
        
        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialVault
                .createRequest([{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                
                    deal_address: deal_address,
                    deal_id: deal_id,
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,
                    oracle_key: oracle_key,
                    oracle_value: proofApprove ? proofApprove.inputs[0] : oracle_value,
                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    privateNewBalance: privateAfterBalance, 
                    privateSenderAmount: privateAmount_from, 
                    privateReceiverAmount: privateAmount_to,
                
                    proof: proofSend.solidityProof, 
                    input: proofSend.inputs,

                    proof_agree: proofAgree.solidityProof, 
                    input_agree: proofAgree.inputs
                }], { gasLimit: BigInt(1_200_000/*1_152_414*/) });
            
            await tx.wait();
        }
        else {
            const tx = await this.vault.confidentialVault
                .createRequest([{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                
                    deal_address: deal_address,
                    deal_id: deal_id,
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,
                    oracle_key: oracle_key,
                    oracle_value: oracle_value,
                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    privateNewBalance: privateAfterBalance, 
                    privateSenderAmount: privateAmount_from, 
                    privateReceiverAmount: privateAmount_to,
                
                    proof: proofSend.solidityProof, 
                    input: proofSend.inputs,

                    proof_agree: proofAgree.solidityProof, 
                    input_agree: proofAgree.inputs
                }]);
            
                await tx.wait();
        }
        return proofSend.inputs[4];
    }
    
    retreive = async (idHash: string, denomination: string) => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequest(idHash);
        const beforeBalance = await this.getBalance(denomination);
    
        const privateAmount = sendRequest.sender.toString().toLowerCase() === walletData.address.toString().toLowerCase() ? sendRequest.private_sender_amount : sendRequest.private_receiver_amount;
        const amount = BigInt(await this.vault.decrypt(privateAmount));
    
        const afterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);
    
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialVault.acceptRequest(idHash, afterBalance, proofReceive.solidityProof, proofReceive.inputs, { gasLimit: BigInt(650_000/*618_821*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialVault.acceptRequest(idHash, afterBalance, proofReceive.solidityProof, proofReceive.inputs);
            await tx.wait();
        }
    }
}