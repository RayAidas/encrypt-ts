/*!
 * Copyright (c) 2015 Sri Harsha <sri.harsha@zenq.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import Algo from "./algo";

const algo = new Algo();

export default class Encrypt {
	public rl;
	public version = '1.0.0'
	
	public init() {
		console.log("version:", this.version);
		console.log("--------------------Applying Encryption algorithm------------------ ");
	}

	public utf8Encode(str: string) {
		return unescape(encodeURIComponent(str));
	};

	public utf8Decode(str: string) {
		try {
			return decodeURIComponent(escape(str));
		} catch (e) {
			return e; // invalid UTF-8? return as-is
		}
	};

	public base64Encode(str: string) {
		if (typeof btoa != 'undefined') return btoa(str); // browser
		// if (typeof Buffer != 'undefined') return new Buffer(this, 'utf8').toString('base64'); // Node.js
		throw new Error('No Base64 Encode');
	};

	public base64Decode(str: string) {
		if (typeof atob != 'undefined') return atob(str); // browser
		// if (typeof Buffer != 'undefined') return new Buffer(this, 'base64').toString('utf8'); // Node.js
		throw new Error('No Base64 Decode');
	};

	public encrypt(plaintext, password, nBits) {
		let blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4)
		if (!(nBits == 128 || nBits == 192 || nBits == 256)) return ''; // standard allows 128/192/256 bit keys
		plaintext = this.utf8Encode(String(plaintext));
		password = this.utf8Encode(String(password));

		// use AES itself to encrypt password to get cipher key (using plain password as source for key
		// expansion) - gives us well encrypted key (though hashed key might be preferred for prod'n use)
		let nBytes = nBits / 8;  // no bytes in key (16/24/32)
		let pwBytes = new Array(nBytes);
		for (let i = 0; i < nBytes; i++) {  // use 1st 16/24/32 chars of password for key
			pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);
		}
		let key = algo.cipher(pwBytes, algo.keyExpansion(pwBytes)); // gives us 16-byte key
		key = key.concat(key.slice(0, nBytes - 16));  // expand key to 16/24/32 bytes long

		// initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A �B.2): [0-1] = millisec,
		// [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
		let counterBlock = new Array(blockSize);

		let nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
		let nonceMs = nonce % 1000;
		let nonceSec = Math.floor(nonce / 1000);
		let nonceRnd = Math.floor(Math.random() * 0xffff);
		// for debugging: nonce = nonceMs = nonceSec = nonceRnd = 0;

		for (let i = 0; i < 2; i++) counterBlock[i] = (nonceMs >>> i * 8) & 0xff;
		for (let i = 0; i < 2; i++) counterBlock[i + 2] = (nonceRnd >>> i * 8) & 0xff;
		for (let i = 0; i < 4; i++) counterBlock[i + 4] = (nonceSec >>> i * 8) & 0xff;

		// and convert it to a string to go on the front of the ciphertext
		let ctrTxt = '';
		for (let i = 0; i < 8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);

		// generate key schedule - an expansion of the key into distinct Key Rounds for each round
		let keySchedule = algo.keyExpansion(key);

		let blockCount = Math.ceil(plaintext.length / blockSize);
		let ciphertxt = new Array(blockCount);  // ciphertext as array of strings

		for (let b = 0; b < blockCount; b++) {
			// set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
			// done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
			for (let c = 0; c < 4; c++) counterBlock[15 - c] = (b >>> c * 8) & 0xff;
			for (let c = 0; c < 4; c++) counterBlock[15 - c - 4] = (b / 0x100000000 >>> c * 8);

			let cipherCntr = algo.cipher(counterBlock, keySchedule);  // -- encrypt counter block --

			// block size is reduced on final block
			let blockLength = b < blockCount - 1 ? blockSize : (plaintext.length - 1) % blockSize + 1;
			let cipherChar = new Array(blockLength);

			for (let i = 0; i < blockLength; i++) {  // -- xor plaintext with ciphered counter char-by-char --
				cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i);
				cipherChar[i] = String.fromCharCode(cipherChar[i]);
			}
			ciphertxt[b] = cipherChar.join('');
		}

		// use Array.join() for better performance than repeated string appends
		let ciphertext = ctrTxt + ciphertxt.join('');
		ciphertext = this.base64Encode(ciphertext);

		return ciphertext;
	};

	public decrypt(ciphertext, password, nBits) {
		let blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
		if (!(nBits == 128 || nBits == 192 || nBits == 256)) return ''; // standard allows 128/192/256 bit keys
		ciphertext = this.base64Decode(String(ciphertext));
		password = this.utf8Encode(String(password));

		// use AES to encrypt password (mirroring encrypt routine)
		let nBytes = nBits / 8;  // no bytes in key
		let pwBytes = new Array(nBytes);
		for (let i = 0; i < nBytes; i++) {
			pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);
		}
		let key = algo.cipher(pwBytes, algo.keyExpansion(pwBytes));
		key = key.concat(key.slice(0, nBytes - 16));  // expand key to 16/24/32 bytes long

		// recover nonce from 1st 8 bytes of ciphertext
		let counterBlock = new Array(8);
		let ctrTxt = ciphertext.slice(0, 8);
		for (let i = 0; i < 8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

		// generate key schedule
		let keySchedule = algo.keyExpansion(key);

		// separate ciphertext into blocks (skipping past initial 8 bytes)
		let nBlocks = Math.ceil((ciphertext.length - 8) / blockSize);
		let ct = new Array(nBlocks);
		for (let b = 0; b < nBlocks; b++) ct[b] = ciphertext.slice(8 + b * blockSize, 8 + b * blockSize + blockSize);
		ciphertext = ct;  // ciphertext is now array of block-length strings

		// plaintext will get generated block-by-block into array of block-length strings
		let plaintxt = new Array(ciphertext.length);

		for (let b = 0; b < nBlocks; b++) {
			// set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
			for (let c = 0; c < 4; c++) counterBlock[15 - c] = ((b) >>> c * 8) & 0xff;
			for (let c = 0; c < 4; c++) counterBlock[15 - c - 4] = (((b + 1) / 0x100000000 - 1) >>> c * 8) & 0xff;

			let cipherCntr = algo.cipher(counterBlock, keySchedule);  // encrypt counter block

			let plaintxtByte = new Array(ciphertext[b].length);
			for (let i = 0; i < ciphertext[b].length; i++) {
				// -- xor plaintxt with ciphered counter byte-by-byte --
				plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
				plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
			}
			plaintxt[b] = plaintxtByte.join('');
		}

		// join array of blocks into single plaintext string
		let plaintext = plaintxt.join('');
		plaintext = this.utf8Decode(plaintext);  // decode from UTF8 back to Unicode multi-byte chars

		return plaintext;
	};

	public getTextEncryptAndSaveToTextFile(filePath, password, nBits) {
		if (!this.rl) throw Error("Command line not supported on this platform");
		// this.rl.question("Enter the text to be encrypted: ", function (answer) {
		//     // TODO: Log the answer in a database
		//     console.log("'" + answer + "' This text will be encrypted and stored in a text file 'encrypted.txt'");
		//     let cipherText = this.encrypt(answer, password, nBits);
		//     fs.writeFile(filePath, cipherText, function () {
		//         console.log("'encrypted.txt' File created in your local directory, if not present refresh your project");
		//     });
		//     this.rl.close();
		// });
	};

	public getTextEncryptAndSaveToJSONFile = function (filePath, password, nBits) {
		if (!this.rl) throw Error("Command line not supported on this platform");
		// this.rl.question("Enter the text to be encrypted: ", function (answer) {
		// 	// TODO: Log the answer in a database
		// 	console.log("'" + answer + "' This text will be encrypted and stored in a text file 'encrypted.txt'");
		// 	let cipherText = this.encrypt(answer, password, nBits);
		// 	this.writeCipherTextToJSON(filePath, { EncryptedText: cipherText }, function () {
		// 		console.log("'encryptedText.JSON' File created in your local directory, if not present refresh your project");
		// 	});
		// 	this.rl.close();
		// });
	};

	public writeCipherTextToJSON(file, obj, options, callback) {
		if (!this.rl) throw Error("Command line not supported on this platform");
		// if (callback == null) {
		// 	callback = options;
		// 	options = {}
		// }

		// let spaces = typeof options === 'object' && options !== null
		// 	? 'spaces' in options
		// 		? options.spaces : this.spaces
		// 	: this.spaces;

		// let str = '';
		// try {
		// 	str = JSON.stringify(obj, options ? options.replacer : null, spaces) + '\n'
		// } catch (err) {
		// 	if (callback) return callback(err, null)
		// }

		// fs.writeFile(file, str, options, callback)
	};
}
