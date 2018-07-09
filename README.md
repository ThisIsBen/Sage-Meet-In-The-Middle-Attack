# Sage-Meet-In-The-Middle-Attack
**The goal of this program is to make use of Meet In The Middle Attack(MITM) to figure out the Key pair used in a double S-AES
encryption.**<br/> 
The following 5 plaintext messages were encrypted by double S-AES using two different keys.<br/> 
Given their corresponding ciphertext messages,<br/> 
we utilize the MITM attack technique to figure out the key pairs used for the encryption.

| 1   | Plaintext:Network Security class is awesome! Ciphertext(binary):00100100011100101001010001011000110001100000001001100101000001010000000001100010110011111011000110101111011100011010010001010001010100001011011010111110000010101101111110110111011000001011010000001011010101100111101011000011000001011000100011110110100111111011101001001010|
| ------------- |:-------------:|
| 2   | Plaintext:Oh yeah! I Love NCKU,IIM~     Ciphertext(binary):111101101001110101100101110001001011111000101010101101111001101001100111110001001101011111000001110101100000100011010100100010101111000101101100010000110110010010110111001111011011100000100100000111101010011| 
| 3   | Plaintext:Initial Impressions of the HTC 168   Ciphertext(binary):00000111110100111100111011010111101101111101101001101011100101010100011111010010101101011100110000000101100010001010000001100001101001101001010100001011010101101101011010011100001101011100110111000011110100011000011111001110010100100000010110010011011100100111010110010000| 
| 4   | Plaintext:Mini-AES: A simplified variant of the Advanced Encryption Standard   Ciphertext(binary):110111001100001010010100011110011001000010000010011100111000011000010010111000111110001111111001101000000110000101101111010101011001111000001001100101111000100111001110001001110011010111001100110010101100001010110111110110101100100000000111001000001011011101101001111001011000111000011010011010100100010111010010100001011101011110001011000001000111100011001110001001110000011111001101000001000111100010101000001000010001010111000001000101111101010101100100100001011011111110111101101000101000010110111110000110100001111101110001| 
| 5   | Plaintext:Chien-Ming Wang KC   Ciphertext(binary):111100000110110111000111110100011111010010001111110111001100001001110100011100110110010000110011101000101000010101100111111001010111111111110110| 

## Execution:
```
sage MITM_Attack.sage
```
It might take about 30 to 40 minutes to figure out the key pair.So, you can go out to enjoy the sun shine after you execute it.

**The program found the Key pair used to encryption the above 5 plaintexts :**
**(key1 , key2)  =  (0101010100110011,0100110100110111)**


## What if I want to use my own plaintext-ciphertext pair to figure out the key pair?
If you want to use your own plaintext-ciphertext pair to figure out the key pair,
replace the plaintext-ciphertext pairs in the main function with yours.
For example, you can import your own plaintext-ciphertext pairs like this in the main function.
```
PC_pairs.append((sageBinaryStr.encoding([Your own plaintext ]),sageBinaryStr([Your own binary ciphertext])))
```

## Reference:
. [Mini-AES Reference Page](http://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/block_cipher/miniaes.html)
