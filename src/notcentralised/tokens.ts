
/* 
 SPDX-License-Identifier: MIT
 Tokens SDK for Typescript v0.9.2069 (tokens.ts)

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

import { utils, Contract, PopulatedTransaction } from 'ethers';
import ConfidentialTreasury from './abi/ConfidentialTreasury.json';

import { encrypt, textToBigInt } from './encryption';
import { genProof } from './proof';

export type SendRequest = {
    idHash: string,
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
    oracle_value_recipient: bigint,
    decimals?: bigint
}

export type Cashflows = {
    lockedOut: SendRequest[], 
    lockedIn: SendRequest[],
}

export type Balance = Cashflows & { 
    privateBalance: bigint, 
    lockedOut: SendRequest[], 
    lockedIn: SendRequest[], 
    balance: bigint, 
    decimals: bigint 
}



export const zeroAddress = '0x0000000000000000000000000000000000000000';

export class Tokens
{
    private tokenDecimalCache : { [key: string]: string } = {};

    vault: NotVault;
    constructor(vault: NotVault){
        this.vault = vault;
    }

    getBalance = async (denomination: string, obligor: string, type : "all" | "in" | "out" | "none" | "public" = "all", groupId? : BigInt) : Promise<Balance> => {
        let _lockedIn: SendRequest[] = [];
        let _lockedOut: SendRequest[] = [];

        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialWallet)
            throw new Error('Wallet is not initialised');
    

        if(!this.vault.confidentialDeal)
            throw new Error('Deal is not initialised');
        
        const group_id = groupId ?? BigInt(0);

        const privateBalance = await this.vault.confidentialWallet?.privateBalanceOf(this.vault.confidentialVault.address, walletData.address, group_id, denomination, obligor);

        let _encryptedBalance = '';
        let _decryptedBalance = BigInt(0);

        if(type === "all" || type === "out"){
            _encryptedBalance = privateBalance;
            
            _decryptedBalance = _encryptedBalance === '' ? BigInt(0) : (BigInt(await this.vault.decrypt(privateBalance)));

            const outNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), true);
            let __lockedOut : any[] = []
            for(let i = 0; i < outNonce; i++)
                __lockedOut.push(await this.vault.confidentialVault.getSendRequestByIndex(walletData.address, group_id, BigInt(0), i, true));

            if(__lockedOut.length > 0){
            
                _lockedOut = await Promise.all(__lockedOut.filter((element: any) => element.denomination === denomination).map(async (element: any) => {
                    const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', `0x${BigInt(element.idHash).toString(16)}`) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, `0x${BigInt(element.idHash).toString(16)}`);
                    
                    const owner = BigInt(element.deal_id) === BigInt(0) ? element.deal_address : await this.vault.confidentialDeal?.ownerOf(BigInt(element.deal_id));
                    
                    const _amount = await this.vault.decrypt(__amount);
                    return {
                        idHash: `0x${BigInt(element.idHash).toString(16)}`,
                        sender: element.sender,

                        owner: owner,
                        
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

        if(type === "all" || type === "in"){
            const intNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), false);
            
            let __lockedIn : any[] = []
            for(let i = 0; i < intNonce; i++)
                __lockedIn.push(await this.vault.confidentialVault.getSendRequestByIndex(walletData.address, group_id, BigInt(0), i, false));

            const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
            const _dealLock = await Promise.all(_deals.map(async deal => {
                const intNonce = await this.vault.confidentialVault?.getNonce(this.vault.confidentialDeal?.address, group_id, deal.tokenId, false);

                let __lockedIn : any[] = []
                for(let i = 0; i < intNonce; i++)
                    __lockedIn.push(await this.vault.confidentialVault?.getSendRequestByIndex(this.vault.confidentialDeal?.address, group_id, deal.tokenId, i, false));

                return __lockedIn;
            }));

            __lockedIn = __lockedIn.concat(_dealLock.flat())

            if(__lockedIn.length > 0)
                _lockedIn = await Promise.all(__lockedIn.filter((element: any) => element.denomination === denomination).map(async element => {
                    const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', `0x${BigInt(element.idHash).toString(16)}`) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, `0x${BigInt(element.idHash).toString(16)}`);

                    const owner = BigInt(element.deal_id) === BigInt(0) ? element.deal_address : await this.vault.confidentialDeal?.ownerOf(BigInt(element.deal_id));

                    const _amount = await this.vault.decrypt(__amount);
                    return {
                        idHash: `0x${BigInt(element.idHash).toString(16)}`,
                        sender: element.sender,

                        owner: owner,

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

        if(type === "none"){
            if (!(denomination in this.tokenDecimalCache)){
                const { balance, decimals } = await this.tokenBalance(denomination);
                return { privateBalance: _decryptedBalance, lockedOut: _lockedOut, lockedIn: _lockedIn, balance: balance, decimals: decimals };
            }
            else{
                return { privateBalance: _decryptedBalance, lockedOut: _lockedOut, lockedIn: _lockedIn, balance: BigInt(0), decimals: BigInt(10 ** Number(this.tokenDecimalCache[denomination])).valueOf() };
            }
        }
        else{
            const { balance, decimals } = await this.tokenBalance(denomination);

            return { privateBalance: _decryptedBalance, lockedOut: _lockedOut, lockedIn: _lockedIn, balance: balance, decimals: decimals };
        }
    }
    
    getCashflows = async (dealId: BigInt, groupId? : BigInt) : Promise<Cashflows> => {
        let _lockedIn: SendRequest[] = [];
        let _lockedOut: SendRequest[] = [];

        const walletData = this.vault.getWalletData();
        if(!walletData.address)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialWallet)
            throw new Error('Wallet is not initialised');
    

        if(!this.vault.confidentialDeal)
            throw new Error('Deal is not initialised');
        
        const group_id = groupId ?? BigInt(0);

        const outNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), true);
        let __lockedOut : any[] = []
        for(let i = 0; i < outNonce; i++)
            __lockedOut.push(await this.vault.confidentialVault.getSendRequestByIndex(walletData.address, group_id, BigInt(0), i, true));

        if(__lockedOut.length > 0){
        
            _lockedOut = await Promise.all(__lockedOut.filter((element: any) => BigInt(element.deal_id) === dealId).map(async (element: any) => {
                const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', `0x${BigInt(element.idHash).toString(16)}`) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, `0x${BigInt(element.idHash).toString(16)}`);
                
                const owner = BigInt(element.deal_id) === BigInt(0) ? element.deal_address : await this.vault.confidentialDeal?.ownerOf(BigInt(element.deal_id));

                let decimals = BigInt(0);

                if (!(element.denomination in this.tokenDecimalCache)){
                    decimals = (await this.tokenBalance(element.denomination)).decimals;
                }
                else{
                    decimals =  BigInt(10 ** Number(this.tokenDecimalCache[element.denomination])).valueOf();
                }
                
                const _amount = await this.vault.decrypt(__amount);
                return {
                    idHash: `0x${BigInt(element.idHash).toString(16)}`,
                    sender: element.sender,

                    owner: owner,
                    
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
                    oracle_value_recipient: BigInt(element.oracle_value_recipient),
                    decimals: decimals
                }
            }));      
        }
        
        const intNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), false);
        
        let __lockedIn : any[] = []
        for(let i = 0; i < intNonce; i++)
            __lockedIn.push(await this.vault.confidentialVault.getSendRequestByIndex(walletData.address, group_id, BigInt(0), i, false));

        const _deals: { tokenId: string, tokenUri:string, accepted:number, created:number, expiry:number }[] = await this.vault.confidentialDeal.getDealByOwner(walletData.address);
        const _dealLock = await Promise.all(_deals.map(async deal => {
            const intNonce = await this.vault.confidentialVault?.getNonce(this.vault.confidentialDeal?.address, group_id, deal.tokenId, false);

            let __lockedIn : any[] = []
            for(let i = 0; i < intNonce; i++)
                __lockedIn.push(await this.vault.confidentialVault?.getSendRequestByIndex(this.vault.confidentialDeal?.address, group_id, deal.tokenId, i, false));

            return __lockedIn;
        }));

        __lockedIn = __lockedIn.concat(_dealLock.flat())

        if(__lockedIn.length > 0)
            _lockedIn = await Promise.all(__lockedIn.filter((element: any) => BigInt(element.deal_id) === dealId).map(async element => {
                const __amount = this.vault.db?.privateAmountOf ? await this.vault.db?.privateAmountOf(this.vault.confidentialVault?.address ?? '', walletData.address ?? '', `0x${BigInt(element.idHash).toString(16)}`) : await this.vault.confidentialWallet?.privateAmountOf(element.sender, this.vault.confidentialVault?.address, walletData.address, `0x${BigInt(element.idHash).toString(16)}`);

                const owner = BigInt(element.deal_id) === BigInt(0) ? element.deal_address : await this.vault.confidentialDeal?.ownerOf(BigInt(element.deal_id));

                const _amount = await this.vault.decrypt(__amount);

                let decimals = BigInt(0);

                if (!(element.denomination in this.tokenDecimalCache)){
                    decimals = (await this.tokenBalance(element.denomination)).decimals;
                }
                else{
                    decimals =  BigInt(10 ** Number(this.tokenDecimalCache[element.denomination])).valueOf();
                }

                return {
                    idHash: `0x${BigInt(element.idHash).toString(16)}`,
                    sender: element.sender,

                    owner: owner,

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
                    oracle_value_recipient: BigInt(element.oracle_value_recipient),
                    decimals: decimals
                }
            }));      

        return { lockedOut: _lockedOut, lockedIn: _lockedIn };   
    }

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

    depositTx = async (denomination: string, obligor: string, amount: bigint, treasurer_secret:string = '') : Promise<{approveTx: PopulatedTransaction, depositTx: PopulatedTransaction, setBalanceTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        // if(!this.vault.db?.setPrivateBalanceMeta){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        // }

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });
        
        const tokenProxy = new Contract(denomination, ConfidentialTreasury.abi, this.vault.signer);
        const approveTx = await tokenProxy.populateTransaction.approveMeta(walletData.address, this.vault.confidentialVault.address, amount);

        const group_id = BigInt(0);
        
        const proof_treasury = await genProof(this.vault, 'approver', { key: denomination, value: textToBigInt(treasurer_secret) });

        const depositTx = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, group_id, denomination, obligor, amount, proofReceive.solidityProof, proofReceive.inputs, {
            policy_type: 'secret',
            proof: proof_treasury.solidityProof,
            input: proof_treasury.inputs,
            signatures: []
        });

        const setBalanceTx = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalanceMeta(
            walletData.address, 
            this.vault.confidentialVault.address,
            group_id,
            denomination,
            obligor,
            privateAfterBalance
        );
    
        return {
            approveTx: approveTx,
            depositTx: depositTx,
            setBalanceTx: setBalanceTx,
            privateAfterBalance: privateAfterBalance
         }
    }

    depositUnfundedTx = async (denomination: string, obligor: string, amount: bigint, treasurer_secret:string = '') : Promise<{depositTx: PopulatedTransaction, setBalanceTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.chainId))
            throw new Error('Vault is not initialised');

        if(!this.vault.confidentialVault)
            throw new Error('Vault is not initialised');

        // if(!this.vault.db?.setPrivateBalanceMeta){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        // }

        const group_id = BigInt(0);

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) + BigInt(amount);
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        
        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const proof_treasury = await genProof(this.vault, 'approver', { key: denomination, value: textToBigInt(treasurer_secret) });
        
        const depositTx = await this.vault.confidentialVault.populateTransaction.depositMeta(walletData.address, group_id, denomination, obligor, 0, proofReceive.solidityProof, proofReceive.inputs, {
            policy_type: 'secret',
            proof: proof_treasury.solidityProof,
            input: proof_treasury.inputs,
            signatures: []
        });

        const setBalanceTx = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalanceMeta(
            walletData.address, 
            this.vault.confidentialVault.address,
            group_id,
            denomination,
            obligor,
            privateAfterBalance
        );
        
        return {
            depositTx: depositTx,
            setBalanceTx: setBalanceTx,
            privateAfterBalance: privateAfterBalance
         }
    }

    withdrawTx = async (denomination:string, obligor: string, amount: bigint, treasurer_secret:string = '') : Promise<{idHash: string, withdrawTx: PopulatedTransaction, setBalanceTx: PopulatedTransaction, privateAfterBalance: string}> => {
        
        const walletData = this.vault.getWalletData();

        if(!(walletData.address && walletData.publicKey && this.vault.chainId && this.vault.confidentialVault))
            throw new Error('Vault is not initialised');

        // if(!this.vault.db?.setPrivateBalanceMeta){
            if(!this.vault.confidentialWallet)
                throw new Error('Wallet is not initialised');
        // }

        const group_id = BigInt(0);
    
        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), true);
        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);    
        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
    
        const proofSend = await genProof(this.vault, 'sender', { 
            sender: walletData.address, 
            senderBalanceBeforeTransfer: beforeBalance.privateBalance, 
            nonce: BigInt(senderNonce),

            denomination: denomination,
            obligor: obligor,

            amount: amount, 
            count: 1,

            deal_address: walletData.address,
            deal_group_id: BigInt(0),
            deal_id: BigInt(0)
        });

        const idHash = utils.solidityKeccak256([
            "uint256", "uint256",

            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256"

        ], [
            proofSend.inputs[4], 0,

            0, 0, 

            0, 0, 
            0, 0, 
        
            0, 0
        ]);

        const proof_treasury = await genProof(this.vault, 'approver', { key: denomination, value: textToBigInt(treasurer_secret) });
        
        const withdrawTx = await this.vault.confidentialVault.populateTransaction.withdrawMeta(walletData.address, group_id, denomination, obligor, amount, proofSend.solidityProof, proofSend.inputs,{
            policy_type: 'secret',
            proof: proof_treasury.solidityProof,
            input: proof_treasury.inputs,
            signatures: []
        });

        const setBalanceTx = await this.vault.confidentialWallet.populateTransaction.setPrivateBalanceMeta(
            walletData.address, 
            this.vault.confidentialVault.address,
            group_id,
            denomination,
            obligor,
            privateAfterBalance
        );

        return {
            idHash: `0x${BigInt(idHash).toString(16)}`,
            withdrawTx: withdrawTx,
            setBalanceTx: setBalanceTx,
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

        oracleKeySender?: bigint | string, 
        oracleValueSender?: bigint | string, 
        oracleKeyRecipient?: bigint | string, 
        oracleValueRecipient?: bigint | string, 

        unlockSender?: number, 
        unlockReceiver?:number,
        dealGroupId?: bigint,
        dealId?: bigint
    ) : Promise<{
        idHash: string, 
        createRequestTx: PopulatedTransaction, 
        setBalanceTx: PopulatedTransaction,
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

        const senderNonce = await this.vault.confidentialVault.getNonce(walletData.address, group_id, BigInt(0), true);

        const beforeBalance = await this.getBalance(denomination, obligor);
        const afterBalance = BigInt(beforeBalance.privateBalance) - BigInt(amount);

        const privateAfterBalance = await encrypt(walletData.publicKey, afterBalance);
        const privateAmount_from = await encrypt(walletData.publicKey, amount);
        const privateAmount_to = await encrypt(counterPublicKey, amount);

        
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


        const proofSend = await genProof(this.vault, 'sender', { 
            sender: walletData.address, 
            senderBalanceBeforeTransfer: BigInt(beforeBalance.privateBalance), 
            nonce: BigInt(senderNonce),

            denomination: denomination,
            obligor: obligor,
            
            amount: amount, 
            count: 1,

            deal_address: deal_address,
            deal_group_id: deal_group_id,
            deal_id: dealId ?? BigInt(0)
        });

        const idHash = utils.solidityKeccak256([
            "uint256", "uint256",

            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256"

            ], [proofSend.inputs[4], 0,

                oracle_address, oracle_owner,

                oracle_key_sender,
                proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                oracle_key_recipient,
                proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                unlock_sender,
                unlock_receiver,
            ]);
        
            
        const createRequestTx = await this.vault.confidentialVault
            .populateTransaction
            .createRequestMeta(
                walletData.address, group_id, 
                [{ 
                    oracle_address: oracle_address,
                    oracle_owner: oracle_owner,

                    oracle_key_sender: oracle_key_sender,
                    oracle_value_sender: proofApproveSender ? proofApproveSender.inputs[0] : oracle_value_sender,
                    oracle_key_recipient: oracle_key_recipient,
                    oracle_value_recipient: proofApproveRecipient ? proofApproveRecipient.inputs[0] : oracle_value_recipient,

                    unlock_sender: unlock_sender,
                    unlock_receiver: unlock_receiver,
                }], 
                {
                    proof: proofSend.solidityProof, 
                    input: proofSend.inputs,
                },
                {
                    denomination: denomination,
                    obligor: obligor,

                    deal_address: deal_address,
                    deal_group_id: deal_group_id,
                    deal_id: deal_id
                },
                false
            );

        const setBalanceTx = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalanceMeta(
            walletData.address, 
            this.vault.confidentialVault.address,
            group_id,
            denomination,
            obligor,
            privateAfterBalance
        );
    
        
        return {
            idHash: `0x${BigInt(idHash).toString(16)}`, 
            createRequestTx: createRequestTx, 
            setBalanceTx: setBalanceTx,
            privateAfterBalance: privateAfterBalance, 
            privateAfterAmount_from: privateAmount_from, 
            privateAfterAmount_to: privateAmount_to
        };
    }

    retreiveTx = async (idHash: string) : Promise<{acceptRequestTx: PopulatedTransaction, setBalanceTx: PopulatedTransaction, privateAfterBalance: string, sendRequest: any}> => {
        const walletData = this.vault.getWalletData();
        if(!(walletData.address && walletData.publicKey && this.vault.confidentialVault && this.vault.chainId && this.vault.confidentialWallet))
            throw new Error('Vault is not initialised');

        const sendRequest = await this.vault.confidentialVault.getSendRequestByID(idHash);

        const beforeBalance = await this.getBalance(sendRequest.denomination, sendRequest.obligor);
        const privateAmount = this.vault.db ? await this.vault.db.privateAmountOf(this.vault.confidentialVault.address, walletData.address, `0x${BigInt(idHash).toString(16)}`) :  await this.vault.confidentialWallet.privateAmountOf(sendRequest.sender, this.vault.confidentialVault.address, walletData.address, idHash);

        const amount = BigInt(await this.vault.decrypt(privateAmount));
        const privateAfterBalance = await encrypt(walletData.publicKey, beforeBalance.privateBalance + amount);

        const proofReceive = await genProof(this.vault, 'receiver', { receiverBalanceBeforeTransfer: beforeBalance.privateBalance, amount: amount });

        const acceptRequestTx = await this.vault.confidentialVault.populateTransaction.acceptRequestMeta(walletData.address, idHash, proofReceive.solidityProof, proofReceive.inputs);

        const setBalanceTx = await this.vault.confidentialWallet?.populateTransaction.setPrivateBalanceMeta(
            walletData.address, 
            this.vault.confidentialVault.address,
            sendRequest.deal_group_id,
            sendRequest.denomination,
            sendRequest.obligor,
            privateAfterBalance
        );
        
        return {
            acceptRequestTx: acceptRequestTx,
            setBalanceTx: setBalanceTx,
            privateAfterBalance: privateAfterBalance,
            sendRequest: sendRequest
        }
    }
}