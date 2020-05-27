# cryptocalc
A Python3 script for encrypting and decrypting data using AES-GCM and ascii hex strings. Ideally for use on an air-gapped Raspberry Pi using the inbuilt hardware random number generator.

## Example

### Encryption

```
$ ./cryptocalc.py -e
Enter plaintext: super secret data 
Enter passphrase: correct horse battery staple
=================================================================================
Encrypted:
Salt: 		b1042b9c1a970e03
IV: 		9edba651959077ea
		d9f665a6
Ciphertext: 	9be071a2e40b3fc1
		20c41e9b30f5126f
		1f288c5b862c1517
		fdfbbd0a4f125956
		8d
=================================================================================
```

### Decryption

```
$ ./cryptocalc.py -d
Enter salt: b1042b9c1a970e03
Enter iv: 9edba651959077ead9f665a6
Enter ciphertext: 9be071a2e40b3fc120c41e9b30f5126f1f288c5b862c1517fdfbbd0a4f1259568d
Enter passphrase: correct horse battery staple
=================================================================================
Decrypted:
super secret data
=================================================================================
```
