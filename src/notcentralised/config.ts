
/* 
 SPDX-License-Identifier: MIT
 Config SDK for Typescript v0.9.569 (config.ts)

  _   _       _    _____           _             _ _              _ 
 | \ | |     | |  / ____|         | |           | (_)            | |
 |  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
 | . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
 | |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
 |_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
 Author: @NumbersDeFi 
*/

export type ContractList = {
    walletAddress: string, 
    vaultAddress: string, 
    dealAddress: string, 
    oracleAddress: string,
    serviceAddress: string,
    accessAddress: string,
    groupAddress: string
}

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
        },
        paymentSignature:{
            key: string,
            wasm: string,
            vkey: string
        },
        policy:{
            key: string,
            wasm: string,
            vkey: string
        }
    },
    contracts: ContractList,
    axios: {
        get: (cid: string) => {},
        post: (fmData: FormData, onUploadProgress: any) => {},
        del: (cid: string) => {},
    }
}

export const contractsTable : Record<string, ContractList > = {
    '5': {               // GOERLI
        walletAddress:   '0x5F4f89bd3B61740F2E8264FE9ff8e2Cdf295B2bF',
        vaultAddress:    '0x4C1fcce4474CEA690Af57f08eE189CaC4f2e4721',
        dealAddress:     '0xe8Fb759ABA61091700eBF85F35b866c751Ba6DD6',
        oracleAddress:   '0xa946D99b5dDdd21688AfBBF16c196052c93577Ba',
        serviceAddress:  '0x9894CE6BB4dFdE24ACD6276D9CF4Fbd20d67d272',
        accessAddress:   '---',
        groupAddress:    '---'
    },
    '153': {              // REDBELLY TESTNET
        walletAddress:   '0xfD53472a51F51F4f7585491848842eB197e0fE3F',
        vaultAddress:    '0x8921BCB3B7D5846a13F360965e63a014E194d7F9',
        dealAddress:     '0x785b10bE3a858Fcb230C42D08eB56A9f4B5DB432',
        oracleAddress:   '0x166d3a2852FCb435D1cFa56Eae2b9A5b18A193B0',
        serviceAddress:  '0xB7B4A248e52f5E5487dbb017129Cc1F0F6A7eDce',
        accessAddress:   '0xC244032DA7250DD7C26ca73C74BA381316CAe1Eb',
        groupAddress:    '---'
    },
    '11155111': {         // SEPOLIA
        walletAddress:   '0x4b8Dfd5BdE2907c9b45E5C392421DE5B31E88313',
        vaultAddress:    '0x38Ad327aDF4c763C0686ED8DBc6fa45c7dAb29AE',
        dealAddress:     '0x52329a088c7d8EBd368fe67a6d3966E3BB42A5BB',
        oracleAddress:   '0x8b2a145b8ccdAfC79DDD3D6bE56Bd513a1e0AA49',
        serviceAddress:  '0x5A95e579944a53370c51760A2db3dF6b96b866F1',
        accessAddress:   '---',
        groupAddress:    '---'
    },
    '296': {             // HEDERA TESTNET
        walletAddress:   '0x7560B9002516B82F5a2f0828D906f82A6f77BfD5',
        vaultAddress:    '0xd8006605Fea3433D54922104eb39Cc8627e50c40',
        dealAddress:     '0x38c084eD2b82A07A8c2DF18f5e3dC5498cCDcD85',
        oracleAddress:   '0xeEBb3548334c30DFeFE07097Cf421c8A729a8209',
        serviceAddress:  '0xCe011732b409bA13329Be37a36b1E129aeAbfac5',
        accessAddress:   '---',
        groupAddress:    '---'
    },
    '31337': {           // LOCALHOST
        walletAddress:   '0xA51c1fc2f0D1a1b8494Ed1FE312d7C3a78Ed91C0',
        vaultAddress:    '0x9A676e781A523b5d0C0e43731313A708CB607508',
        dealAddress:     '0x0B306BF915C4d645ff596e518fAf3F9669b97016',
        oracleAddress:   '0x959922bE3CAee4b8Cd9a407cc3ac1C251C2007B1',
        serviceAddress:  '0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE',
        accessAddress:   '0x610178dA211FEF7D417bC0e6FeD39F05609AD788',
        groupAddress:    '0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e'
    },
    '84531': {           // BASE GOERLI
        walletAddress:   '0xF972E1A76F08c377bF0DB8ed52a231EE99bD0b41',
        vaultAddress:    '0x9d68228C8E043630041Cf08f911D2EC329390555',
        dealAddress:     '0xFCC3B351310c2E16035E2126cee14175F5350c91',
        oracleAddress:   '0xbbf1D9AE5919E25567e17FE0e5187f35F6F562a6',
        serviceAddress:  '0x24A4d3335f88e59FA672093226D666B1D9CAACAf',
        accessAddress:   '---',
        groupAddress:    '---'
    }
};

export const getConfig = (
    chainId?: string, 
    proofBase?: string, 
    customTable?: any, 
    custom_axios?: {
        get: (cid: string) => {}, 
        post: (fmData: FormData, onUploadProgress: any) => {}, 
        del: (cid: string) => {} }
    ) : Config => {

        const ipfs_gateway_url= `https://api.pinata.cloud/pinning/`;

        return {
            contracts: chainId ? customTable ?? contractsTable[chainId] : undefined,
            proofs: Object.assign(
                {}, ...[
                { key: 'receiver', value: 'HashReceiver' }, 
                { key: 'sender', value: 'HashSender' }, 
                { key: 'approver', value: 'HashApprover' }, 
                { key: 'paymentSignature', value: 'HashPaymentSignature' }, 
                { key: 'textExpiryData', value: 'TextExpiryData' }, 
                { key: 'textData', value: 'TextData' }, 
                { key: 'numericalData', value: 'NumericalData' },
                { key: 'alphaNumericalData', value: 'AlphaNumericalData' },
                { key: 'policy', value: 'Policy' },
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