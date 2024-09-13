/* 
SPDX-License-Identifier: MIT
Encryption SDK for Typescript v0.9.1869 (encryption.ts)

_   _       _    _____           _             _ _              _ 
| \ | |     | |  / ____|         | |           | (_)            | |
|  \| | ___ | |_| |     ___ _ __ | |_ _ __ __ _| |_ ___  ___  __| |
| . ` |/ _ \| __| |    / _ \ '_ \| __| '__/ _` | | / __|/ _ \/ _` |
| |\  | (_) | |_| |___|  __/ | | | |_| | | (_| | | \__ \  __/ (_| |
|_| \_|\___/ \__|\_____\___|_| |_|\__|_|  \__,_|_|_|___/\___|\__,_|
                                                                    
                                                                    
Author: @NumbersDeFi 
*/


import * as metaEncryption from "@metamask/eth-sig-util";
import * as EthCrypto from "eth-crypto";
const CryptoJS = require('crypto-js');

export const encryptedBySecret = (secret: string, data: string) : string => CryptoJS.AES.encrypt(JSON.stringify(data), secret).toString();

export const decryptBySecret = (secret: string, data: string) : string =>  JSON.parse(CryptoJS.AES.decrypt(data , secret).toString(CryptoJS.enc.Utf8));

export const encrypt = async (pk_to: string, message: any) => {
    const encrypted = await EthCrypto.encryptWithPublicKey(pk_to, JSON.stringify(message));
    return EthCrypto.cipher.stringify(encrypted);
}

export const sign = async (from_privateKey: string, message: any) => {

    const signature = EthCrypto.sign(
        from_privateKey,
        EthCrypto.hash.keccak256(JSON.stringify(message))
    );

    return {
        message: message,
        signature: signature
    };
}

export const recoverSignature = (payload : { message: any, signature: string}) => {
    const senderAddress = EthCrypto.recoverPublicKey(
        payload.signature,
        EthCrypto.hash.keccak256(JSON.stringify(payload.message))
    );

    return {message: payload.message, signer: senderAddress };
}

export const encryptSign = async (from_privateKey: string, to_publicKey: string, message: any) => {

    const payload = await sign(from_privateKey, JSON.stringify(message));
    const encrypted = await EthCrypto.encryptWithPublicKey(to_publicKey, JSON.stringify(payload));

    return EthCrypto.cipher.stringify(encrypted);
}

const decryptionCache : { [key: string]: any } = {};
export const decrypt = async (privateKey: string, message: any) => {
    if(message && (message.toString() in decryptionCache)){
        return decryptionCache[message.toString()];
    }
    const encryptedObject = EthCrypto.cipher.parse(message);

    const decrypted = await EthCrypto.decryptWithPrivateKey(
        privateKey,
        encryptedObject
    );

    const decryptedPayload = JSON.parse(decrypted);
    decryptionCache[message.toString()] = decryptedPayload;
    return decryptionCache[message.toString()];
}

export const decryptSigned = async (privateKey: string, message: any) => {
    if(message && (message.toString() in decryptionCache)){
        return decryptionCache[message.toString()];
    }
    const encryptedObject = EthCrypto.cipher.parse(message);

    const decrypted = await EthCrypto.decryptWithPrivateKey(
        privateKey,
        encryptedObject
    );

    const decryptedPayload = JSON.parse(decrypted);

    // check signature
    const senderAddress = EthCrypto.recover(
        decryptedPayload.signature,
        EthCrypto.hash.keccak256(decryptedPayload.message)
    );

    return {message: decryptedPayload.message, signer: senderAddress };
}

export const metaMaskEncrypt = (publicKey: string, data: string): string => {
    // Returned object contains 4 properties: version, ephemPublicKey, nonce, ciphertext
    // Each contains data encoded using base64, version is always the same string
    const enc = metaEncryption.encrypt({
        publicKey: publicKey,
        data: data,
        version: 'x25519-xsalsa20-poly1305',
    });

    // We want to store the data in smart contract, therefore we concatenate them
    // into single Buffer
    const buf = Buffer.concat([
        Buffer.from(enc.ephemPublicKey, 'base64'),
        Buffer.from(enc.nonce, 'base64'),
        Buffer.from(enc.ciphertext, 'base64'),
    ]);

    // In smart contract we are using `bytes[112]` variable (fixed size byte array)
    // you might need to use `bytes` type for dynamic sized array
    // We are also using ethers.js which requires type `number[]` when passing data
    // for argument of type `bytes` to the smart contract function
    // Next line just converts the buffer to `number[]` required by contract function
    // THIS LINE IS USED IN OUR ORIGINAL CODE:
    // return buf.toJSON().data;

    // Return just the Buffer to make the function directly compatible with decryptData function
    return buf.toString('base64');
    // return buf.toString();
}

export const metaMaskDecrypt = (account: string, data: string, metaMaskDecryptCallback: (data: string) => Promise<string>): Promise<string> => {

    let dataBuffer = Buffer.from(data, 'base64');
    // Reconstructing the original object outputed by encryption
    const structuredData = {
        version: 'x25519-xsalsa20-poly1305',
        ephemPublicKey: dataBuffer.slice(0, 32).toString('base64'),
        nonce: dataBuffer.slice(32, 56).toString('base64'),
        ciphertext: dataBuffer.slice(56).toString('base64'),
    };
    // Convert data to hex string required by MetaMask
    const ct = `0x${Buffer.from(JSON.stringify(structuredData), 'utf8').toString('hex')}`;
    // Send request to MetaMask to decrypt the ciphertext
    // Once again application must have acces to the account
    return metaMaskDecryptCallback(ct);
}

export const textToBigInt = (text: string): bigint => {
    // Convert each character to its ASCII code and concatenate the codes
    let result = '';
    
    for (const char of text) {
      // Get ASCII code of the character
      const asciiCode = char.charCodeAt(0);
      
      // Pad the ASCII code to ensure it has three digits (e.g., '097' for 'a')
      result += asciiCode.toString().padStart(3, '0');
    }
  
    // Convert the concatenated string of ASCII codes to a BigInt
    return BigInt(result);
}

export const bigIntToText = (bigIntValue: bigint): string => {
    // Convert BigInt to a string to process each ASCII code segment
    const bigIntString = bigIntValue.toString();
  
    let text = '';
  
    // Iterate over the string in chunks of 3 digits (since each ASCII code is 3 digits)
    for (let i = 0; i < bigIntString.length; i += 3) {
      // Extract a 3-digit substring
      const asciiCodeStr = bigIntString.substring(i, i + 3);
  
      // Convert the ASCII code string to a number
      const asciiCode = parseInt(asciiCodeStr, 10);
  
      // Convert the ASCII code to its corresponding character and append to the text
      text += String.fromCharCode(asciiCode);
    }
  
    return text;
}
  