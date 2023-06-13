/* 
 SPDX-License-Identifier: MIT
 Service Bus SDK for Typescript v0.4.0 (servicebus.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/


import { NotVault, hederaList } from './notvault';

import { genProof } from './proof';

export class ServiceBus
{
    vault: NotVault
    
    constructor(vault: NotVault){
        this.vault = vault;
    }

    setValue = async (key: BigInt, value: BigInt) : Promise<void> =>  {
        if(!(this.vault.confidentialServiceBus && this.vault.chainId))
            throw new Error('Vault is not initialised');

        const proof = await genProof(this.vault, 'approver', { key: key, value: value});

        if(hederaList.includes(this.vault.chainId)){
            const tx = await this.vault.confidentialServiceBus.setValue(proof.solidityProof, proof.inputs, { gasLimit: BigInt(300_000/*291_582*/) });
            await tx.wait();
        }
        else{
            const tx = await this.vault.confidentialServiceBus.setValue(proof.solidityProof, proof.inputs);
            await tx.wait();
        }
    }

    getValue = async (address: string, key: BigInt) : Promise<BigInt> =>  {
        if(!(this.vault.confidentialServiceBus && this.vault.chainId))
            throw new Error('Vault is not initialised');

        return await this.vault.confidentialServiceBus.getValue(address, key);
    }
}