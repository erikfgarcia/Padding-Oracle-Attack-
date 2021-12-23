import sys, os
from Crypto.Cipher import AES
counter = 0
mode = AES.MODE_CBC
BLOCK_SIZE = 128
NUMBER_OF_BYTES = BLOCK_SIZE//8 # 16 per block
key = 'Crypto is cool!!'

#Inicialization Vector
#IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

#Inicialization Vector
IV ='\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x49\x6e\x74\x56\x65\x63' # hex representation of "encryptionIntVec"

##################################################################
################  AES CBC Encryption Decryption ##################
##################################################################

# Encryption
def encryption(text):
    encryptor = AES.new(key.encode('utf8'), mode, IV=IV.encode('utf8'))
    formatted_text = padding(text) # add padding to the text
    return encryptor.encrypt(formatted_text.encode('utf8'))

# Decryption "Our padding oracle (checkPadding()) has exclusive access to this"
def decryption(ciphertext):
    decryptor = AES.new(key.encode('utf8'), mode, IV=IV.encode('utf8'))
    return decryptor.decrypt(ciphertext)

# This adds b bytes with value b
def padding(text):
    b = NUMBER_OF_BYTES - (len(text) % NUMBER_OF_BYTES)
    return text + chr(b)*b # padding

###################################################################
#################  Padding Oracle Attack  #########################
###################################################################


def paddingOracle(ciphertext):

    text_side = len(ciphertext)
    number_of_block = text_side//NUMBER_OF_BYTES
    decrypted = bytes()

    if (text_side % NUMBER_OF_BYTES) != 0:
        print("ciphertext must be multiple of 16 bytes")
        exit(0)

    for i in range(number_of_block, 0, -1): # loops each block

        # This is the current block we are working with
        encrypted_block = ciphertext[(i - 1) * NUMBER_OF_BYTES:(i) * NUMBER_OF_BYTES]

        if i == 1: # If it is the first encrypted block, we use the IV
            prev_encrypted_block = bytearray(IV.encode("ascii"))
        else:
            prev_encrypted_block = ciphertext[(i - 2) * NUMBER_OF_BYTES:(i - 1) * NUMBER_OF_BYTES]

        decrypted_block = bytearray(IV.encode("ascii"))
        modified_block = prev_encrypted_block

        padding = 0
        # Now we check each byte in the block
        for j in range(NUMBER_OF_BYTES, 0, -1):
            padding += 1
            #
            for value in range(0, 256):
                # building tampered message for oracle to check
                modified_block = bytearray(modified_block)
                modified_block[j - 1] = (modified_block[j - 1] + 1) % 256
                tampered_encrypted_message = bytes(modified_block) + encrypted_block

                # Check with oracle if tampered message is ok
                if checkPadding(tampered_encrypted_message):
                    # building decrypted block
                    decrypted_block[-padding] = prev_encrypted_block[-padding] ^ modified_block[-padding]  ^ padding
                    # composition of byte value
                    for k in range(1, padding + 1):
                        modified_block[-k] = prev_encrypted_block[-k] ^ decrypted_block[-k] ^ padding + 1
                    break
        # composition of decrypted Message
        decrypted = bytes(decrypted_block) + bytes(decrypted)

    return decrypted[:-decrypted[-1]]  # Remove padding

# This is the padding oracle
def checkPadding(ciphertext):

    to_return = True
    global counter
    counter += 1 # this counts the number of times this function is called
    data = decryption(ciphertext) # decrypts ciphertext using AES CBC decryption
    last_byte = data[-1] # has the number of bytes appended for padding

    if last_byte < 1 or last_byte > 16: # check if last byte has a valid value
        to_return = False
    else:
        for i in range(0, last_byte): # checks for correct value in bytes used for padding
            if last_byte != data[-1-i]:
                to_return = False
    return to_return

###########################################################################################

usage = """
Usage:
    * python padding_oracle_attack.py <file_name1.txt> <file_name2.txt>
      encrypts file_name1.txt and outputs the ciphertext file_name2.txt
      (file_name1.txt has to exist prior calling padding_oracle_attack.py)

    * python padding_oracle_attack.py <file_name.txt> 
      decrypts file_name.txt (The cipher) and displays the message and the Counter
"""
if __name__ == '__main__':
    if len(sys.argv) == 3:
        f = open(sys.argv[1], 'r')
        f_content = f.read()
        encrypted = open(sys.argv[2],'w')
        encrypted.write(encryption(f_content).hex())
        f.close()
        encrypted.close()
    elif len(sys.argv) == 2:
        f = open(sys.argv[1], 'r')
        f_content = f.read()
        #print( "This is the cipher:", f_content)
        print("\nDecrypted message: ", paddingOracle(bytes.fromhex(f_content)).decode("ascii"))
        print("Counter: ", counter)
        f.close()
    else:
        print(usage)
