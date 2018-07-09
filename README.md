# Sage-Meet-In-The-Middle-Attack
**The goal of this program is to make use of Meet In The Middle Attack(MITM) to figure out the Key pair used in a double S-AES
encryption.**
The following five plaintext messages were encrypted by double S-AES using two different keys. 
Given their corresponding ciphertext messages,
we utilize the MITM attack technique to figure out the key pairs used for the encryption.

| 1       | Plaintext:
Network Security class is awesome!
Ciphertext (binary):
0010010001110010100101000101100011000110000000100110010100000101000000000110001011
00111110110001101011110111000110100100010100010101000010110110101111100000101011011
11110110111011000001011010000001011010101100111101011000011000001011000100011110110
100111111011101001001010
          | 
| ------------- |:-------------:| 
| 2      | Plaintext:
Oh yeah! I Love NCKU, IIM~
Ciphertext (binary):
111101101001110101100101110001001011111000101010101101111001101001100111110001001101
01111100000111010110000011000110101001000101011110001011011000100001101100100101101
11001111011011100000100100000111101010011
 | 
|3    | Plaintext:
Initial Impressions of the HTC 168
Ciphertext (binary):
000001111101001111001110110101111011011111011010011010111001010101000111110100101011
01011100110000000101100010001010000001100001101001101001010100001011010101101101011
01001110000110101110011011100001111010001100001111100111001010010000001011001001101
1100100111010110010000
     |   
| 4 | Plaintext:
Mini-AES: A simplified variant of the Advanced Encryption Standard
Ciphertext (binary):
11011100110000101001010001111001100100001000001001110011100001100001001011100011111
000111111100110100000011000010110111101010101100111100000100110010111100010011100111
00010011100110101110011001100101011000010101101111101101011001000000001110010000010
11011101101001111001011000111000011010011010100100010111010010100001011101011110001
01100000100011110001100111000100111000001111100110100000100011110001010100000100001
00010101110000010001011111010101011001001000010110111111101111011010001010000101101
11110000110100001111101110001
      |   
| 5 | Plaintext:
Chien-Ming Wang KC
Ciphertext (binary):
111100000110110111000111110100011111010010001111110111001100001001110100011100110110
010000110011101000101000010101100111111001010111111111110110     |   
