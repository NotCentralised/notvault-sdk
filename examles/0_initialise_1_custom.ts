/*
Context: Typescript code for a custom configuration that specifies the connections prior to initilisation
*/

// 1) import necessary libraries
import { NotVault, getConfig } from '@notcentralised/notvault-sdk';
import { ethers } from 'ethers';

// 2) instantiate the NotVault class
const vault = new NotVault();

// 3) create an JSON RPC connection
const customHttpProvider = new ethers.providers.JsonRpcProvider('... RPC Host ...');
const signer = new ethers.Wallet('... Private Key ...', customHttpProvider);

// 4) set the chainId and proofBase variables
const chainId = '...';
const proofBase = '...';

// 5) set a custom table with contract addresses depending on your chain. You are welcome to use the contracts already deployed by NotCentralised.
const contractsTable = {
    walletAddress:  '...',
    vaultAddress:   '...',
    dealAddress:    '...',
    oracleAddress:  '...'
};

// 6) set a custom connection to IPFS.
const ipfs_gateway_url= `https://api.pinata.cloud/pinning/`
const custom_axios_get = (cid: string) => { 
    return {
        method: 'get',
        url: `https://cf-ipfs.com/ipfs/${cid}`
    }
};
const custom_axios_post = (fmData: FormData, onUploadProgress: any) => { 
    return {
        method: 'post',
        url: `${ipfs_gateway_url}/pinFileToIPFS`,
        data: fmData,
        maxContentLength: Number.POSITIVE_INFINITY,
        headers: {
            "Content-Type": `multipart/form-data; boundery=${(fmData as any)._boundary}`,
            pinata_api_key: '...',
            pinata_secret_api_key: '...'
        },
        onUploadProgress: onUploadProgress
    }
};
const custom_axios_del = (cid: string) => { 
    return {
        method: 'get',
        url: `${ipfs_gateway_url}/unpin/${cid}`,
        headers: {
            pinata_api_key: '...',
            pinata_secret_api_key: '...'
        }
    }
};
const axiosConfig = {
    get: custom_axios_get,
    post: custom_axios_post,
    del: custom_axios_del
};

// 6) create the config object for the initialisation
const config = getConfig(chainId, proofBase, contractsTable, axiosConfig);

// 7) initialise the vault object by setting the tables above and the call-back functions that manage the file operations on IPFS.
vault.init('... Chain ID ...', signer, config);