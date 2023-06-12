
/* 
 SPDX-License-Identifier: MIT
 Config SDK for Typescript v0.4.0 (config.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/


export type Config = {
    proofs: {
        receiver:{
            key: string,
            wasm: string,
            vkey: string
        },
        sender:{
            key: string,
            wasm: string,
            vkey: string
        },
        approver:{
            key: string,
            wasm: string,
            vkey: string
        },
        textExpiryData:{
            key: string,
            wasm: string,
            vkey: string
        },
        textData:{
            key: string,
            wasm: string,
            vkey: string
        },
        numericalData:{
            key: string,
            wasm: string,
            vkey: string
        },
        alphaNumericalData:{
            key: string,
            wasm: string,
            vkey: string
        }
    },
    contracts: { 
        walletAddress: string, 
        vaultAddress: string, 
        dealAddress: string, 
        oracleAddress: string 
    },
    axios: {
        get: (cid: string) => {},
        post: (fmData: FormData, onUploadProgress: any) => {},
        del: (cid: string) => {},
    }
}

export const contractsTable : Record<string, any> = {
    '5': {              // GOERLI
        walletAddress:  '0x5F4f89bd3B61740F2E8264FE9ff8e2Cdf295B2bF',
        vaultAddress:   '0x4C1fcce4474CEA690Af57f08eE189CaC4f2e4721',
        dealAddress:    '0xe8Fb759ABA61091700eBF85F35b866c751Ba6DD6',
        oracleAddress:  '0xa946D99b5dDdd21688AfBBF16c196052c93577Ba'
    },
    '11155111': {        // SEPOLIA
        walletAddress:  '0x4b8Dfd5BdE2907c9b45E5C392421DE5B31E88313',
        vaultAddress:   '0x38Ad327aDF4c763C0686ED8DBc6fa45c7dAb29AE',
        dealAddress:    '0x52329a088c7d8EBd368fe67a6d3966E3BB42A5BB',
        oracleAddress:  '0x8b2a145b8ccdAfC79DDD3D6bE56Bd513a1e0AA49'
    },
    '296': {            // HEDERA TESTNET
        walletAddress:  '0x7560B9002516B82F5a2f0828D906f82A6f77BfD5',
        vaultAddress:   '0xd8006605Fea3433D54922104eb39Cc8627e50c40',
        dealAddress:    '0x38c084eD2b82A07A8c2DF18f5e3dC5498cCDcD85',
        oracleAddress:  '0xeEBb3548334c30DFeFE07097Cf421c8A729a8209'
    },
    '31337': {          // LOCALHOST
        walletAddress:  '0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6',
        vaultAddress:   '0x610178dA211FEF7D417bC0e6FeD39F05609AD788',
        dealAddress:    '0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e',
        oracleAddress:  '0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0'
    }
};

export const getConfig = (
    chainId: string, 
    proofBase?: string, 
    customTable?: any, 
    custom_axios?: {
        get: (cid: string) => {}, 
        post: (fmData: FormData, onUploadProgress: any) => {}, 
        del: (cid: string) => {} }
    ) : Config => {

        const ipfs_gateway_url= `https://api.pinata.cloud/pinning/`;

        return {
            contracts: customTable ?? contractsTable[chainId],
            proofs: Object.assign(
                {}, ...[
                { key: 'receiver', value: 'HashReceiver' }, 
                { key: 'sender', value: 'HashSender' }, 
                { key: 'approver', value: 'HashApprover' }, 
                { key: 'minCommitment', value: 'HashMinCommitment' }, 
                { key: 'textExpiryData', value: 'TextExpiryData' }, 
                { key: 'textData', value: 'TextData' }, 
                { key: 'numericalData', value: 'NumericalData' },
                { key: 'alphaNumericalData', value: 'AlphaNumericalData' } 
                ].map(element => ({
                    [element.key]: {
                        key:    (proofBase ?? process.env.PUBLIC_URL) + `/zkp/${element.value}_0001.zkey`,
                        wasm:   (proofBase ?? process.env.PUBLIC_URL) + `/zkp/${element.value}.wasm`,
                        vkey:   (proofBase ?? process.env.PUBLIC_URL) + `/zkp/${element.value}_verification_key.json`
                    }
                }))),
            axios: custom_axios ?? {
                get: (cid: string) => { 
                    return {
                        method: 'get',
                        url: `https://cf-ipfs.com/ipfs/${cid}`
                    }
                },
                post: (fmData: FormData, onUploadProgress: any) => { 
                    return {
                        method: 'post',
                        url: `${ipfs_gateway_url}/pinFileToIPFS`,
                        data: fmData,
                        maxContentLength: Number.POSITIVE_INFINITY,
                        headers: {
                            "Content-Type": `multipart/form-data; boundery=${(fmData as any)._boundary}`,
                            pinata_api_key: process.env.PINATA_API_KEY,
                            pinata_secret_api_key: process.env.PINATA_SECRET_API_KEY
                        },
                        onUploadProgress: onUploadProgress
                    }
                },
                del: (cid: string) => { 
                    return {
                        method: 'get',
                        url: `${ipfs_gateway_url}/unpin/${cid}`,
                        headers: {
                            pinata_api_key: process.env.PINATA_API_KEY,
                            pinata_secret_api_key: process.env.PINATA_SECRET_API_KEY
                        }
                    }
                }
            }
        }
};