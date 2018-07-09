from sage.crypto.util import bin_to_ascii
from sage.crypto.util import ascii_to_bin
from sage.crypto.block_cipher.miniaes import MiniAES
sageBinaryStr = BinaryStrings()
maes = MiniAES()
S_AES_key_length=16


def nth_key(index):
	key='{0:016b}'.format(index)
	return sageBinaryStr(key)

	

def createCipherKeyPair(plain_text, key):
    """helper function used for multiprocessing"""
    #print "current key: %s"%key
    return (maes(plain_text, key, algorithm="encrypt"), key)



def meet_in_the_middle(PC_pairs):
    """Implements a meet-in-the-middle attack on DES.
    Arguments:
        
        PC_pairs -- a list of (plain text, cipher text)-tuples
        
    """

    plain_text, cipher_text = PC_pairs[0]

    # generator for the key candidates
    
    #create a list of all possible keys
    key_generator = [nth_key(i) for i in range(0, 2**S_AES_key_length)]

   

    #create a dict with pair "cipher_text,key"
    table = dict([createCipherKeyPair(plain_text, key) for key in key_generator])
    
    '''
    print (table)

    for key in key_generator:
		print key
    '''


                             
    print "Size of Encryption table and key of first S-AES : %d"%len(table)


    
    print "Cracking cipher_text"
    
    
    
    
    for key in key_generator:
        candidate = maes(cipher_text, key, algorithm="decrypt")
        
        if candidate in table:
            print "Found key: (%s, %s)"%(table[candidate], key)
            for plain, cipher in PC_pairs[1:]:
                if not maes(cipher, key, algorithm="decrypt") == maes(plain, table[candidate], algorithm="encrypt"):
                    continue  # incorrect candidate

            return (table[candidate], key)
    

def main():
	
	print("Attacking Double S-AES Encryption...")
	
	#contruct a list of (plain text, cipher text)-tuples 
	PC_pairs=[]

	'''
	#use my own PC pairs
	PC_pairs.append((sageBinaryStr.encoding("Bean"),sageBinaryStr("10000111000100000011001101101000")))

	PC_pairs.append((sageBinaryStr.encoding("Chen"),sageBinaryStr("00001110100010010011010000111000")))

	#correct answer(key1,key2) = ("0000000000001010","0000000000100000")
	'''


	
	PC_pairs.append((sageBinaryStr.encoding("Chien-Ming Wang KC"),sageBinaryStr("111100000110110111000111110100011111010010001111110111001100001001110100011100110110010000110011101000101000010101100111111001010111111111110110")))

	PC_pairs.append((sageBinaryStr.encoding("Network Security class is awesome!"),sageBinaryStr("00100100011100101001010001011000110001100000001001100101000001010000000001100010110011111011000110101111011100011010010001010001010100001011011010111110000010101101111110110111011000001011010000001011010101100111101011000011000001011000100011110110100111111011101001001010")))

	PC_pairs.append((sageBinaryStr.encoding("Oh yeah! I Love NCKU, IIM~"),sageBinaryStr("1111011010011101011001011100010010111110001010101011011110011010011001111100010011010111110000011101011000001100011010100100010101111000101101100010000110110010010110111001111011011100000100100000111101010011")))


	PC_pairs.append((sageBinaryStr.encoding("Initial Impressions of the HTC 168"),sageBinaryStr("00000111110100111100111011010111101101111101101001101011100101010100011111010010101101011100110000000101100010001010000001100001101001101001010100001011010101101101011010011100001101011100110111000011110100011000011111001110010100100000010110010011011100100111010110010000")))

	PC_pairs.append((sageBinaryStr.encoding("Mini-AES: A simplified variant of the Advanced Encryption Standard"),sageBinaryStr("110111001100001010010100011110011001000010000010011100111000011000010010111000111110001111111001101000000110000101101111010101011001111000001001100101111000100111001110001001110011010111001100110010101100001010110111110110101100100000000111001000001011011101101001111001011000111000011010011010100100010111010010100001011101011110001011000001000111100011001110001001110000011111001101000001000111100010101000001000010001010111000001000101111101010101100100100001011011111110111101101000101000010110111110000110100001111101110001")))
	
	
	
	#Use Meet in the middle algorithm to break double S-AES

	Found_key_pairs = meet_in_the_middle(PC_pairs)
    
	if Found_key_pairs:
		print("Found key pairs: ({},{})".format(*Found_key_pairs))
	else:
		print("Did not find keys!")


if __name__ == '__main__':
	main()