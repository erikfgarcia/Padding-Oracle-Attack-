Padding Oracle Attack  Erik Garcia

The padding_oracle_attack.py is an implementation that shows the weaknesses of CBC mode of operation when using PKCS#7 padding

This implemetation uses Hex ecodding, so the challenge ciphertext has been converted from Base64 to Hex

Decryption of the challenge ciphertext:

The enemy knows the system
Claude Shannon


Useage: 
 
1) This implementation can encrypt a text file using  AES-CBS mode encryption

	This is how to encrypt a text file:
 
	* python padding_oracle_attack.py <file_name1.txt> <file_name2.txt>

	This encrypts an existing file_name1.txt and outputs the ciphertext file_name2.txt

	Example: 

		* python padding_oracle_attack.py plaintext.txt ciphertext.txt


	Note: plaintext.txt has to exists prior calling padding_oracle_attack.py


2) This implemetation can decrypt a cipthertext using a padding oracle attacks and show the number of calls to checkPadding()

	This is how to decrypt a ciphertext: 

	* python padding_oracle_attack.py <file_name.txt>
	
	Example: 

		* python padding_oracle_attack.py ciphertext.txt


        This decrypts file_name.txt (which is a ciphertext) and displays the message and the Counter 
  
	if you want to decrypt the challenge ciphertext:
		* python padding_oracle_attack.py challenge_ciphertext.txt
