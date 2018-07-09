# Sage-Meet-In-The-Middle-Attack
**The goal of this program is to make use of Meet In The Middle Attack(MITM) to figure out the Key pair used in a double S-AES
encryption.**
The following five plaintext messages were encrypted by double S-AES using two different keys. 
Given their corresponding ciphertext messages,
we utilize the MITM attack technique to figure out the key pairs used for the encryption.

| 1   | Plaintext:Network Security class is awesome!    Ciphertext(binary):00100100011100101001010001011000110001100000001001100101000001010000000001100010110011111011000110101111011100011010010001010001010100001011011010111110000010101101111110110111011000001011010000001011010101100111101011000011000001011000100011110110100111111011101001001010| 
| ------------- |:-------------:|
| 2   | Plaintext:Oh yeah! I Love NCKU,IIM~    Ciphertext(binary):111101101001110101100101110001001011111000101010101101111001101001100111110001001101011111000001110101100000100011010100100010101111000101101100010000110110010010110111001111011011100000100100000111101010011| 
| ------------- |:-------------:|
