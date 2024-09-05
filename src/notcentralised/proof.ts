/* 
 SPDX-License-Identifier: MIT
 Proof SDK for Typescript v0.9.1469 (proof.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/
import { NotVault } from './notvault';
const snarkjs = require("snarkjs");
const fs = require('fs').promises;

interface IIndexable {
    [key: string]: any;
}

export const genProof = async (vault: NotVault, name: string, input: any) => {
    if(!vault.config)
        throw new Error('Vault is not initialised');
    const createWasm = (vault.config.proofs as IIndexable)[name].wasm;
    const createZkey = (vault.config.proofs as IIndexable)[name].key;

    const { proof, publicSignals } = await makeProof(input, createWasm, createZkey);

    const solidityProof = proofToSolidityInput(proof);
    return {
        proof: proof,
        solidityProof: solidityProof,
        inputs: publicSignals,
    }
}

export const verifyProof = async (vault: NotVault, name: string, proof: any) => {
    if(!vault.config)
        throw new Error('Vault is not initialised');

    const createZkey = (vault.config.proofs as IIndexable)[name].vkey;

    return await verProof(createZkey, proof.inputs, proof.proof);
}

const makeProof = async (_proofInput: any, _wasm: string, _zkey: string) : Promise<{ proof: string, publicSignals: string[]}> => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(_proofInput, _wasm, _zkey);
    return { proof, publicSignals };
}

// eslint-disable-next-line
const verProof = async (_verificationkey: string, signals: any, proof: any) => {

    let vkey = {}

    try{
        vkey = await fetch(_verificationkey).then(function (res) {
            return res.json();
        });
    }
    catch {
        vkey = JSON.parse(await fs.readFile(_verificationkey, 'utf-8'));
    }

    const res = await snarkjs.groth16.verify(vkey, signals, proof);
    return res;
}

const proofToSolidityInput = (proof: any): string => {
    const proofs: string[] = [
      proof.pi_a[0], proof.pi_a[1],
      proof.pi_b[0][1], proof.pi_b[0][0],
      proof.pi_b[1][1], proof.pi_b[1][0],
      proof.pi_c[0], proof.pi_c[1],
    ];
    const flatProofs = proofs.map(p => BigInt(p));
    return "0x" + flatProofs.map(x => toHex32(x)).join("")
}

const toHex32 = (num: BigInt) => {
    let str = num.toString(16);
    while (str.length < 64) str = "0" + str;
    return str;
}