/*
Context: Typescript code for managing Files
*/

// 1) import necessary libraries
import { NotVault, Files, FileEntry } from '@notcentralised/notvault-sdk';

// 2) instantiate the NotVault and Files classes
const vault = new NotVault();
const files = new Files(vault);

// 3) add new file
const newFilesList : FileEntry[] = await files.add(
    '... File Name ...', 
    '... Super secret text, usually in Base64 format when dealing with binary data ...', 
    (event: any) => {
        const percent = Math.floor((event.loaded / event.total) * 100);
        console.log(`Progress ${percent}%`);
    }
);

// 4) get the contents of a file given its CID.
const retreivedFile : FileEntry = await files.get(`... File CID in IPFS ...`);

// 5) list all the files in a list linked to a specific wallet.
const allFiles : FileEntry[] = await files.list();

// 6) Remove a file from a private list.
const newFilesAfterRemoval : FileEntry[] = await files.remove(`... File CID in IPFS ...`);
