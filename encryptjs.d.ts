export const version: string;

export function decrypt(ciphertext: any, password: any, nBits: any): any;

export function encrypt(plaintext: any, password: any, nBits: any): any;

export function getTextEncryptAndSaveToJSONFile(filePath: any, password: any, nBits: any): void;

export function getTextEncryptAndSaveToTextFile(filePath: any, password: any, nBits: any): void;

export function init(): void;

export function writeCipherTextToJSON(file: any, obj: any, options: any, callback: any): any;