
/* 
 SPDX-License-Identifier: MIT
 Tokens SDK for Typescript v0.9.569 (tokens.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { NotVault } from './notvault';

import * as EthCrypto from "eth-crypto";

import { Contract, PopulatedTransaction } from 'ethers';
import ConfidentialTreasury from './abi/ConfidentialTreasury.json';

import { encrypt } from './encryption';
import { genProof } from './proof';

export type SendRequest = {
    idHash: bigint,
    sender: string,
    amount: bigint,
    created: number,
    unlock_sender: number,
    unlock_receiver: number,
    redeemed: number,
    active: boolean,

    amount_hash: bigint,
    
    deal_address: string,
    deal_group_id: string,
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

    getBalance = async (denomination: string, obligor: string, groupId? : BigInt) : Promise<Balance> => {
        let _lockedIn: SendRequest[] = [];
        let _lockedOut: SendRequest[] = [];

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
        
        // const group_id = groupId ?? walletData.groupId ?? BigInt(0);
        const group_id = groupId ?? BigInt(0);

        const privateBalance = this.vault.db?.privateBalanceOf ? await this.vault.db?.privateBalanceOf(walletData.address, group_id.toString(), this.vault.confidentialVault.address, denomination, obligor) : await this.vault.confidentialWallet?.privateBalanceOf(this.vault.confidentialVault.address, walletData.address, denomination);

        let _encryptedBalance = '';
        let _decryptedBalance = BigInt(0);
    
        
        if (_encryptedBalance !== privateBalance) {
            _encryptedBalance = privateBalance;
            
            _decryptedBalance = _encryptedBalance === '' ? BigInt(0) : (BigInt(await this.vault.decrypt(privateBalance)));

            const __lockedOut = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, group_id, BigInt(0), true);
            
            if(__lockedOut.length > 0){
            
                _lockedOut = await Promise.all(__lockedOut.filter((element: any) => element.denomination === denomination).map(async (element: any) => {
                    const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', element.idHash.toString()) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
                    const _amount = await this.vault.decrypt(__amount);
                    return {
                        idHash: element.idHash,
                        sender: element.sender,
                        // recipient: element.recipient,
                        amount: BigInt(_amount),
                        created: Number(element.created),
                        unlock_sender: Number(element.unlock_sender),
                        unlock_receiver: Number(element.unlock_receiver),
                        redeemed: Number(element.redeemed),
                        active: element.active,

                        amount_hash: BigInt(element.amount_hash),
                        
                        deal_address: element.deal_address,
                        deal_group_id: element.deal_group_id,
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

        let __lockedIn : SendRequest[] = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, group_id, BigInt(0), false);

        // console.log("--- __lockedIn: ", group_id, " <-> ", __lockedIn)

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
        const _dealLock = await Promise.all(_deals.map(async deal => {
            // console.log("--- _deals: ", deal)
            return await this.vault.confidentialVault?.getSendRequestByAddress(this.vault.confidentialDeal?.address, group_id, deal.tokenId, false);
        }));

        __lockedIn = __lockedIn.concat(_dealLock.flat())

        if(__lockedIn.length > 0)
            _lockedIn = await Promise.all(__lockedIn.filter((element: any) => element.denomination === denomination).map(async element => {
                const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
                const _amount = await this.vault.decrypt(__amount);
                return {
                    idHash: element.idHash,
                    sender: element.sender,
                    // recipient: element.recipient,
                    amount: BigInt(_amount),
                    created: Number(element.created),
                    unlock_sender: Number(element.unlock_sender),
                    unlock_receiver: Number(element.unlock_receiver),
                    redeemed: Number(element.redeemed),
                    active: element.active,

                    amount_hash: BigInt(element.amount_hash),

                    deal_address: element.deal_address,
                    deal_group_id: element.deal_group_id,
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

        return { privateBalance: _decryptedBalance, lockedOut: _lockedOut, lockedIn: _lockedIn, balance: balance, decimals: decimals };
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

        const group_id = BigInt(0);
        
        const tx1 = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, group_id, denomination, obligor, amount, proofReceive.solidityProof, proofReceive.inputs);
        
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

        const group_id = BigInt(0);

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tx = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, group_id, denomination, obligor, 0, proofReceive.solidityProof, proofReceive.inputs);
        
        return {
            depositTx: tx,
            privateAfterBalance: privateAfterBalance
         }
    }

    withdrawTx = async (denomination:string, obligor: string, amount: bigint) : Promise<{idHash: string, withdrawTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }

        const group_id = BigInt(0);
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id);

        const beforeBalance = await this.getBalance(denomination, obligor);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });



        const tx1 = await this.vault.confidentialVault.populateTransaction.withdrawMeta(walletData.address, group_id, denomination, obligor, amount, proofSend.solidityProof, proofSend.inputs);
        
        return {
            idHash: proofSend.inputs[4],
            withdrawTx: tx1,
            privateAfterBalance: privateAfterBalance,
        };
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
        dealGroupId?: BigInt,
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

        const group_id = BigInt(0);

        const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet.getPublicKey(destinationAddress);

        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id);

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


        const deal_address = destinationAddress === '' ? this.vault.confidentialDeal.address : destinationAddress;
        const deal_group_id = dealGroupId ?? BigInt(0);
        const deal_id = dealId ?? BigInt(0);
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
            obligor: obligor,
            amount: amount, 
            oracle_address: oracle_address, oracle_owner: oracle_owner, 

            oracle_key_sender: oracle_key_sender, oracle_value_sender: oracle_value_sender, 
            oracle_key_recipient: oracle_key_recipient, oracle_value_recipient: oracle_value_recipient, 
            
            unlock_sender: unlock_sender, unlock_receiver: unlock_receiver,

            deal_address: deal_address,
            deal_group_id: deal_group_id,
            deal_id: dealId ?? BigInt(0)
        });

        const idHash = proofSignature.inputs[1];
            
        const tx1 = await this.vault.confidentialVault
            .populateTransaction
            .createRequestMeta(walletData.address, group_id, [{ 
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
                }], deal_address, deal_group_id, deal_id, false);
        
        return {
            idHash: idHash, 
            createRequestTx: tx1, 
            privateAfterBalance: privateAfterBalance, 
            privateAfterAmount_from: privateAmount_from, 
            privateAfterAmount_to: privateAmount_to
        };
    }

    retreiveTx = async (idHash: string, denomination: string, obligor: string) : Promise<{acceptRequestTx: PopulatedTransaction, privateAfterBalance: string}> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        const beforeBalance = await this.getBalance(denomination, obligor);

        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault.address, walletData.address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);
    
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