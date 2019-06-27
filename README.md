# Discord-Hack-Week-Harpocrates
A simple to use discord cryptography bot 

Harpocrates has 2 main cyther methods:

	czrCode is a Cesar encryption method it takes arguments mode chrset czrkey and message
		mode is a Harpocrates mode class this can be found by rerquesting allsets with argument modes
		chrset is Harpocrates characterset (chrset) class this can be found by rerquesting allsets with argument chrsets
		czrkey is the key (must be an integer) this is the displacement value for example if the input is ABCDEFGHIJKLMNOPQRSTUVWXYZ and the key is 5 the output is FGHIJKLMNOPQRSTUVWXYZABCDE
		message is a string
	fernet is a much more sophisticated cipher method it takes in arguments hashMethod mode key (cannot include spaces ‘ ’) message
		hashMethod is a Harpocrates hash class this can be found by rerquesting allsets with argument hashes
		mode is a Harpocrates mode class this can be found by rerquesting allsets with argument modes
		key that’s a single string with no whitespaces in itself 
		message is a string

