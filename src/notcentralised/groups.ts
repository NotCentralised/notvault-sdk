/* 
 SPDX-License-Identifier: MIT
 Groups SDK for Typescript v0.9.0 (deals.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { encrypt } from './encryption';

import { PopulatedTransaction, utils } from 'ethers';

import * as EthCrypto from "eth-crypto";

import { Tokens, Balance, zeroAddress } from './tokens';
import { NotVault } from './notvault';
import { genProof } from './proof';

export type Policy = {
    policy_type: string,
    upper: bigint,
    lower: bigint,
    
    start: number,
    expiry: number,
    counter: number,
    maxUse: number,

    callers: string[],
    minSignatories: number
}

export class Groups
{
    vault: NotVault;
    tokens: Tokens;
    
    constructor(vault: NotVault, tokens: Tokens){
        this.vault = vault;
        this.tokens = tokens
    }

    registerTx = async(members: { address: string, id: BigInt }[]) : Promise<(PopulatedTransaction | undefined)>=> {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialGroup && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const policies = await this.vault.confidentialGroup.populateTransaction.registerGroupMeta(walletData.address, members.map(x=>x.address), members.map(x=>x.id));
        return policies;
    }

    setWalletTx = async(id: bigint, address: string) : Promise<(PopulatedTransaction | undefined)>=> {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialGroup && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const tx = await this.vault.confidentialGroup.populateTransaction.setGroupWallet(walletData.address, id, address);
        return tx;
    }

    getPolicies = async (
        groupId: BigInt
    ) : Promise<BigInt[]> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialGroup && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const policies = await this.vault.confidentialGroup.getPolicies(groupId);

        return policies;
    }

    addPolicyTx = async (
        groupId: BigInt,
        policy: Policy,
        amount: BigInt,
        deal: { address: string, group_id: BigInt, id: BigInt}
    ) : Promise<(PopulatedTransaction | undefined)> => {

        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialWallet && this.vault.confidentialDeal && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const hashContactId = EthCrypto.hash.keccak256(deal.address.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = deal.address;
    
        let policyId = '';
        if(policy.policy_type === 'transfer') {
            const proofPolicy = await genProof(this.vault, 'policy', { 
                group_id: groupId,
                amount: amount,
                upper: policy.upper,
                lower: policy.lower,

                start: policy.start,
                expiry: policy.expiry,
                max_use: policy.maxUse,

                deal_address: destinationAddress || this.vault.confidentialDeal.address,
                deal_group_id: deal.group_id,
                deal_id: deal.id
            });

            policyId = proofPolicy.inputs[0];
        }
        else{
            throw new Error('Not Implemented Yet') 
        }
        
        // const tx = await this.vault.confidentialGroup?.populateTransaction.addPolicy(walletData.address, deal.group_id, policyId, policy);
        const tx = await this.vault.confidentialGroup?.populateTransaction.addPolicyMeta(walletData.address, groupId, policyId, { policy_type: policy.policy_type, start: policy.start, expiry: policy.expiry, counter: 0, maxUse: policy.maxUse, callers: policy.callers, minSignatories: policy.minSignatories });
        return tx;
    }

    getBalance = async (id: BigInt, denomination: string, obligor: string) : Promise<Balance> => {
        return this.tokens.getBalance(denomination, obligor, id);
    }

    // SEND FROM GROUP
    sendTx = async (
        group: { id: BigInt, vault: NotVault, groups: Groups},
        policy: Policy,
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
        dealId?: BigInt,

    ) : Promise<{
        idHash: string, 
        createRequestTx: PopulatedTransaction, 
        privateAfterBalance: string, 
        privateAfterAmount_from: string, 
        privateAfterAmount_to: string
    }> => {
        const walletData = this.vault.getWalletData();
        const address = walletData.address;
        // const publicKey = walletData.publicKey;
        const groupId = group.id;//walletData.groupId;

        const publicKey = group.vault.getWalletData().publicKey;
        
        if(!(address && publicKey && this.vault.chainId && this.vault.confidentialVault && this.vault.confidentialDeal && this.vault.confidentialWallet && this.vault.confidentialGroup))
            throw new Error('Vault is not initialised');
        
        const hashContactId = EthCrypto.hash.keccak256(destination.toLowerCase().trim());
        let destinationAddress = this.vault.db ? await this.vault.db.getAddressByContactId(hashContactId) : await this.vault.confidentialWallet.getAddressByContactId(hashContactId);
        if(destinationAddress === zeroAddress)
            destinationAddress = destination;

        const counterPublicKey =this.vault.db ? await this.vault.db.getPublicKey(destinationAddress) : await this.vault.confidentialWallet.getPublicKey(destinationAddress);
        

        // const senderNonce = await this.vault.confidentialVault.getNonce(address, groupId ?? BigInt(0));
        const senderNonce = await this.vault.confidentialVault.getNonce(group.vault.getWalletData().address, groupId ?? BigInt(0));

        const beforeBalance = await group.groups.getBalance(group.id, denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);

        const privateAfterBalance = await encrypt(publicKey, afterBalance);
        const privateAmount_from = await encrypt(publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { sender: address, senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), amount: BigInt(amount), nonce: BigInt(senderNonce) });
        
        let proofApproveSender;
        if(oracleKeySender && oracleValueSender)
            proofApproveSender = await genProof(this.vault, 'approver', { key: oracleKeySender, value: oracleValueSender });

        let proofApproveRecipient;
        if(oracleKeyRecipient && oracleValueRecipient)
            proofApproveRecipient = await genProof(this.vault, 'approver', { key: oracleKeyRecipient, value: oracleValueRecipient});


        const deal_address = destinationAddress === '' ? this.vault.confidentialDeal.address : destinationAddress;
        const deal_group_id = BigInt(0);
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

        const proofPolicy = await genProof(this.vault, 'policy', { 
            group_id: groupId,
            amount: amount,
            upper: policy.upper,
            lower: policy.lower,

            start: policy.start,
            expiry: policy.expiry,
            max_use: policy.maxUse,

            deal_address: deal_address,
            deal_group_id: deal_group_id,
            deal_id: dealId ?? BigInt(0)
        });


        const idHash = proofSignature.inputs[1];

        const messageHash = utils.solidityKeccak256(['bytes'], [proofPolicy.solidityProof]);
        
        const prefixedHash = utils.hashMessage(utils.arrayify(messageHash));
        const flatSig = await this.vault?.signer?.signMessage(utils.arrayify(prefixedHash));
    
        const tx1 = await this.vault.confidentialGroup
            .populateTransaction
            .createRequestMeta(
                walletData.address, 
                // group.vault.getWalletData().address,
                groupId ?? BigInt(0), 
                this.vault.confidentialVault.address,
                [{ 
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
                }], 
                [{
                    policy_type: 'transfer',
                    proof: proofPolicy.solidityProof,
                    input: proofPolicy.inputs,
                    signatures: [flatSig]
                }],
                deal_address, deal_group_id, deal_id, false);
        
        return {
            idHash: idHash, 
            createRequestTx: tx1, 
            privateAfterBalance: privateAfterBalance, 
            privateAfterAmount_from: privateAmount_from, 
            privateAfterAmount_to: privateAmount_to
        };
    }

    // ACCEPTS TO GROUP
    retreiveTx = async (group: { id: BigInt, vault: NotVault, groups: Groups}, idHash: string, denomination: string, obligor: string) : Promise<{acceptRequestTx: PopulatedTransaction, privateAfterBalance: string}> => {
        const walletData = this.vault.getWalletData();
        const address = walletData.address;
        // const publicKey = walletData.publicKey;

        if(!(address && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet && this.vault.confidentialGroup))
            throw new Error('Vault is not initialised');
        
        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        // const beforeBalance = await this.tokens.getBalance(denomination, obligor);
        const beforeBalance = await group.groups.getBalance(group.id, denomination, obligor);

        // const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault.address, address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, address, idHash);
        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault.address, group.vault.getWalletData().address ?? '', idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, group.vault.getWalletData().address ?? '', idHash);
        
        // const publicKey = await this.vault.db?.getPublicKey(sendRequest.sender) ?? '';
        const publicKey = group.vault.getWalletData().publicKey ?? '';

        const amount = BigInt(await group.vault.decrypt(privateAmount));
        const afterBalance = await encrypt(publicKey, beforeBalance.privateBalance + amount);
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const tx1 = await this.vault.confidentialGroup.populateTransaction.acceptRequestMeta(address, group.id, this.vault.confidentialVault.address, idHash, proofReceive.solidityProof, proofReceive.inputs);
        
        return {
            acceptRequestTx: tx1,
            privateAfterBalance: afterBalance
        }
    }
}