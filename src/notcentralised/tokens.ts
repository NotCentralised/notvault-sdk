
/* 
 SPDX-License-Identifier: MIT
 Tokens SDK for Typescript v0.6.0 (tokens.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

import { NotVault, WalletDB, hederaList } from './notvault';

import * as EthCrypto from "eth-crypto";

import { Contract, PopulatedTransaction } from 'ethers';
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
    // private_sender_amount: string,
    // private_receiver_amount: string,
    
    deal_address: string,
    deal_id: bigint,
    denomination: string,
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

    getBalance = async (denomination: string) : Promise<Balance> => {
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


        const privateBalance = this.vault.db?.privateBalanceOf ? await this.vault.db?.privateBalanceOf(this.vault.confidentialVault.address, walletData.address, denomination) : await this.vault.confidentialWallet?.privateBalanceOf(this.vault.confidentialVault.address, walletData.address, denomination);
        
        if (this._encryptedBalance !== privateBalance) {
            this._encryptedBalance = privateBalance;
            this._decryptedBalance = this._encryptedBalance === '' ? BigInt(0) : (BigInt(await this.vault.decrypt(privateBalance)));

            const __lockedOut = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, BigInt(0), true);
            
            if(__lockedOut.length > 0){
            
                this._lockedOut = await Promise.all(__lockedOut.filter((element: any) => element.denomination === denomination).map(async (element: any) => {
                    const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
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
                        // private_sender_amount: element.private_sender_amount,
                        // private_receiver_amount: element.private_receiver_amount,

                        deal_address: element.deal_address,
                        deal_id: BigInt(element.deal_id),
                        denomination: element.denomination,

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

        let __lockedIn : SendRequest[] = await this.vault.confidentialVault.getSendRequestByAddress(walletData.address, BigInt(0), false);

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
        const _dealLock = await Promise.all(_deals.map(async deal => {
            return await this.vault.confidentialVault?.getSendRequestByAddress(this.vault.confidentialDeal?.address, deal.tokenId, false);
        }));

        __lockedIn = __lockedIn.concat(_dealLock.flat())

        if(__lockedIn.length > 0)
            this._lockedIn = await Promise.all(__lockedIn.filter((element: any) => element.denomination === denomination).map(async element => {
                const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, element.idHash);
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
                    // private_sender_amount: element.private_sender_amount,
                    // private_receiver_amount: element.private_receiver_amount,

                    deal_address: element.deal_address,
                    deal_id: BigInt(element.deal_id),
                    denomination: element.denomination,
                    
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

        if(!this.vault.confidentialWallet)
            throw new Error('Wallet is not initialised');

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
            const tx1 = await this.vault.confidentialVault.deposit(denomination, amount, proofReceive.solidityProof, proofReceive.inputs, { gasLimit: BigInt(600_000/*552_191*/) });
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, privateAfterBalance) : await this.vault.confidentialWallet.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        else{
            const tx1 = await this.vault.confidentialVault.deposit(denomination, amount, proofReceive.solidityProof, proofReceive.inputs);
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, privateAfterBalance) : await this.vault.confidentialWallet.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
    }

    depositTx = async (denomination: string, amount: bigint) : Promise<{approveTx: PopulatedTransaction, depositTx: PopulatedTransaction, setPrivateBalanceTx: PopulatedTransaction | undefined}> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }

        const beforeBalance = await this.getBalance(denomination);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tokenProxy = new Contract(denomination, ProxyToken.abi, this.vault.signer);
        const tx = await tokenProxy.populateTransaction.approve(this.vault.confidentialVault.address, amount);
        
        const tx1 = await this.vault.confidentialVault.populateTransaction.deposit(denomination, amount, proofReceive.solidityProof, proofReceive.inputs);
        const tx2 = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);

        return {
            approveTx: tx,
            depositTx: tx1,
            setPrivateBalanceTx: tx2
        }
    }

    withdraw = async (denomination:string, amount: bigint) : Promise<string> => {
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });

        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault.withdraw(denomination, amount, proofSend.solidityProof, proofSend.inputs, { gasLimit: BigInt(400_000/*374_927*/) });
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, privateAfterBalance) : await this.vault.confidentialWallet?.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        else{
            const tx1 = await this.vault.confidentialVault.withdraw(denomination, amount, proofSend.solidityProof, proofSend.inputs);
            await tx1.wait();
            const tx2 = this.vault.db?.setPrivateBalance ? await this.vault.db?.setPrivateBalance(walletData.address, this.vault.confidentialVault.address, denomination, privateAfterBalance) : await this.vault.confidentialWallet?.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);
            if(tx2.wait)
                await tx2.wait();
        }
        
        return proofSend.inputs[4];
    }

    withdrawTx = async (denomination:string, amount: bigint) : Promise<{idHash: string, withdrawTx: PopulatedTransaction, setPrivateBalanceTx: PopulatedTransaction | undefined}> => {
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        if(!this.vault.db?.setPrivateBalance){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        }
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address);
    
        const beforeBalance = await this.getBalance(denomination);
    
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
        
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount, nonce: BigInt(senderNonce) });

        const tx1 = await this.vault.confidentialVault.populateTransaction.withdraw(denomination, amount, proofSend.solidityProof, proofSend.inputs);
        const tx2 = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalance(this.vault.confidentialVault.address, denomination, privateAfterBalance);
        
        return {
            idHash: proofSend.inputs[4],
            withdrawTx: tx1,
            setPrivateBalanceTx: tx2,  
        };
    }

    send = async (
            denomination: string, 
            destination: string, 
            amount: bigint, 
            oracleAddress?: string, 
            oracleOwner?: string, 

            oracleKeySender?: number, 
            oracleValueSender?: number, 
            oracleKeyRecipient?: number, 
            oracleValueRecipient?: number, 

            unlockSender?: number, 
            unlockReceiver?:number,
            dealId?: BigInt, 
            expiry?: number
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
    
        const beforeBalance = await this.getBalance(denomination);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);
    
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), amount: BigInt(amount), nonce: BigInt(senderNonce) });
        
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

        const proofAgree = await genProof(this.vault, 'minCommitment', { 
            amount: amount, minAmount: amount, oracle_owner: oracle_owner, 

            oracle_key_sender: oracle_key_sender, oracle_value_sender: oracle_value_sender, 
            oracle_key_recipient: oracle_key_recipient, oracle_value_recipient: oracle_value_recipient, 
            
            unlock_sender: unlock_sender, unlock_receiver: unlock_receiver,
            expiry: expiry
        });
    
        const idHash = proofSend.inputs[4];
        
        if(hederaList.includes(this.vault.chainId)){
            const tx1 = await this.vault.confidentialVault
                .createRequest([{ 
                    recipient: destinationAddress, 
                    denomination: denomination, 
                
                    deal_address: deal_address,
                    deal_id: deal_id,
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    // privateNewBalance: privateAfterBalance, 
                    // privateSenderAmount: privateAmount_from, 
                    // privateReceiverAmount: privateAmount_to,
                
                    proof: proofSend.solidityProof, 
                    input: proofSend.inputs,

                    proof_agree: proofAgree.solidityProof, 
                    input_agree: proofAgree.inputs
                }], { gasLimit: BigInt(1_200_000/*1_152_414*/) });
            
            await tx1.wait();

            const tx2 = this.vault.db ? 
                await this.vault.db.setPrivateBalance(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    denomination,
                    privateAfterBalance
                ) 
                : 
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
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
                
                    deal_address: deal_address,
                    deal_id: deal_id,
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                
                    // privateNewBalance: privateAfterBalance, 
                    // privateSenderAmount: privateAmount_from, 
                    // privateReceiverAmount: privateAmount_to,
                
                    proof: proofSend.solidityProof, 
                    input: proofSend.inputs,

                    proof_agree: proofAgree.solidityProof, 
                    input_agree: proofAgree.inputs
                }], { gasLimit: BigInt(1_200_000/*1_152_414*/) });
            
            await tx1.wait();

            const tx2 = this.vault.db ? 
                await this.vault.db.setPrivateBalance(
                    walletData.address,
                    this.vault.confidentialVault.address,
                    denomination,
                    privateAfterBalance
                ) 
                : 
                await this.vault.confidentialWallet
                    .setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    privateAfterBalance
                );

            if(tx2.wait)
                await tx2.wait();

            const tx3 = this.vault.db ? 
                await this.vault.db.setPrivateAmount(
                    this.vault.confidentialVault.address,
                    this.vault.getWalletData().address,
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
        destination: string, 
        amount: bigint, 
        oracleAddress?: string, 
        oracleOwner?: string, 

        oracleKeySender?: number, 
        oracleValueSender?: number, 
        oracleKeyRecipient?: number, 
        oracleValueRecipient?: number, 

        unlockSender?: number, 
        unlockReceiver?:number,
        dealId?: BigInt, 
        expiry?: number
    ) : Promise<{
        idHash: string, 
        createRequestTx: PopulatedTransaction, 
        setPrivateBalanceTx: PopulatedTransaction, 
        setPrivateAmountTx_from: PopulatedTransaction, 
        setPrivateAmountTx_to: PopulatedTransaction
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

        const beforeBalance = await this.getBalance(denomination);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);

        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        const proofSend = await genProof(this.vault, 'sender', { sender: walletData.address, senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), amount: BigInt(amount), nonce: BigInt(senderNonce) });
        
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

        const proofAgree = await genProof(this.vault, 'minCommitment', { 
            amount: amount, minAmount: amount, oracle_owner: oracle_owner, 

            oracle_key_sender: oracle_key_sender, oracle_value_sender: oracle_value_sender, 
            oracle_key_recipient: oracle_key_recipient, oracle_value_recipient: oracle_value_recipient, 
            
            unlock_sender: unlock_sender, unlock_receiver: unlock_receiver,
            expiry: expiry
        });

        const idHash = proofSend.inputs[4];
            
        const tx1 = await this.vault.confidentialVault
            .populateTransaction.createRequest([{ 
                recipient: destinationAddress, 
                denomination: denomination, 
            
                deal_address: deal_address,
                deal_id: deal_id,
                oracle_address: oracle_address,
                oracle_owner: oracle_owner,

                oracle_key_sender: oracle_key_sender,
                oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                oracle_key_recipient: oracle_key_recipient,
                oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                unlock_sender: unlock_sender,
                unlock_receiver: unlock_receiver,
            
                // privateNewBalance: privateAfterBalance, 
                // privateSenderAmount: privateAmount_from, 
                // privateReceiverAmount: privateAmount_to,
            
                proof: proofSend.solidityProof, 
                input: proofSend.inputs,

                proof_agree: proofAgree.solidityProof, 
                input_agree: proofAgree.inputs
            }], { gasLimit: BigInt(1_200_000/*1_152_414*/) });
        
        const tx2 =  
            await this.vault.confidentialWallet
                .populateTransaction.setPrivateBalance(
                this.vault.confidentialVault.address,
                denomination,
                privateAfterBalance
            );

        const tx3 =
            await this.vault.confidentialWallet
            .populateTransaction.setPrivateAmount(
                this.vault.confidentialVault.address,
                this.vault.getWalletData().address,
                idHash,
                privateAmount_from
            );

        const tx4 = 
            await this.vault.confidentialWallet
            .populateTransaction.setPrivateAmount(
                this.vault.confidentialVault.address,
                destinationAddress,
                idHash,
                privateAmount_to
            );

        return {
            idHash: idHash, 
            createRequestTx: tx1, 
            setPrivateBalanceTx: tx2, 
            setPrivateAmountTx_from: tx3, 
            setPrivateAmountTx_to: tx4
        };
    }
    
    retreive = async (idHash: string, denomination: string) => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        const beforeBalance = await this.getBalance(denomination);

        console.log('------- beforeBalance 1: ', beforeBalance)

        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);
    
        console.log('------- retreive 2: ', privateAmount)
        const amount = BigInt(await this.vault.decrypt(privateAmount));

        console.log('------- amount 3: ', amount)
    
        const afterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);

        console.log('------- afterBalance 4: ', amount)
    
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
                    afterBalance
                )
                :
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
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
                    afterBalance
                )
                :
                await this.vault.confidentialWallet.setPrivateBalance(
                    this.vault.confidentialVault.address,
                    denomination,
                    afterBalance
                );

            if(tx2.wait)
                await tx2.wait();
        }
    }

    retreiveTx = async (idHash: string, denomination: string) : Promise<{acceptRequestTx: PopulatedTransaction, setPrivateBalanceTx: PopulatedTransaction}> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);
        const beforeBalance = await this.getBalance(denomination);

        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);
    
        const amount = BigInt(await this.vault.decrypt(privateAmount));

        const afterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);

        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const tx1 = await this.vault.confidentialVault.populateTransaction.acceptRequest(idHash, proofReceive.solidityProof, proofReceive.inputs);
        
        const tx2 = await this.vault.confidentialWallet.populateTransaction.setPrivateBalance(
                this.vault.confidentialVault.address,
                denomination,
                afterBalance
            );

        return {
            acceptRequestTx: tx1,
            setPrivateBalanceTx: tx2
        }
    }
}