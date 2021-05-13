

     ______    __   __  _______  _______  ___   _______  __   __ 
    |    _ |  |  | |  ||       ||       ||   | |       ||  | |  |
    |   | ||  |  | |  ||  _____||  _____||   | |    ___||  |_|  |
    |   |_||_ |  |_|  || |_____ | |_____ |   | |   |___ |       |
    |    __  ||       ||_____  ||_____  ||   | |    ___||_     _|
    |   |  | ||       | _____| | _____| ||   | |   |      |   |  
    |___|  |_||_______||_______||_______||___| |___|      |___|  

# Intro
Russify is a stego tool that hides secrets in a cover text by using some homographic chars from Cyrillic dictionaries. We relyon Pastebin to exfiltrate the data. The download of the actual data from Pastebin is done thoughthe Google Translate Service, this might bypass security boundaries that prevent the victim fromaccessing Pastebin directly.

# Description
## Stego algorithm
The algorithm to hide the secret is simple but effective. Once we have the secret in binary, we set acounter to 0 and we start iterating over each character of the cover message. We hide the secret bitby bit, when we encounter one of the characters shown in the image above we apply the followinglogic: if the first bit of the secret is a 0 we leave the occidental character, otherwise we swap it withits Cyrillic counterpart. Then we increment the counter by 1 to point to the next bit of the secretand so on. It can noted that the length of the secret depends on the number of occurrences of theselected characters in the cover text. Before hiding the secret, we check whether it is going to fit ornot, and we warn the user to provide a bigger cover text if needed. When all the secret its hidden,an invisible character is appended at the end of the resulting stego-text to mark its ending.We have considered the possibility that the cover text already includes Cyrillic characters. In thiscase, if the current bit of the secret is a 1, the character remains as Cyrillic, otherwise if it is a 0,the character is swapped by its Occidental counterpart.

## Compression and encryption
We must not forget that steganography can successfully hide the existence of a secret, but it doesnot provide confidentiality nor integrity in itself. Besides, the stego algorithm has a size constraintwhich can limit the length of the message to be hidden. For this reason we will compress the data,and encrypt it.It is crucial to perform this process in the correct order: the message must first be compressed andthen encrypted, otherwise the compression would be of no use. The compression algorithm chosenis zlib (deflate format) which will reduce the length of the message (as long as it is not random) inorder to increase the capacity of the tool.The encryption algorithm chosen is AES256. This algorithm is extensively used for encryption incountless different tools, and is considered to be secure as of today.  The key for encryption isgenerated using the PBKDF2 key derivation algorithm. Using this function makes it much moredifficult to crack the encryption key, and the usage of a salt avoids precomputation-based attacks. Apossible improvement of the tool on this front would be to dynamically generate the key using, forexample, ECDHE (Ephemeral Elliptic Curve Diffie-Hellman Key Exchange) as most C2 frameworksdo, as to reduce the impact of a potential compromise of the server.

## Covert channel using google translate
The tool is prepared to upload the stego message to Pastebin. Pastebin is a web where any user canupload any content and share the link with others to share information. Pastebin can sometimes beblocked by internal DNS or firewalls due to it being widely used by malware and threat actors. Atthis point, we decided to implement a way to access to it using Google Translate API.Google Translate can be used to translate any web from one language to other. In this case, wedon’t need to translate anything. We use Google translate services as a proxy to access to any web,in this case, Pastebin

# Usage
The tools offers 4 different modes. The upload/download pair uses the stego encryption/decryption plus Pastebin to store the message and Google Translate’s API to download it. The hide/extract pair is just the stego part of the tool, relying on local files rather than Pastebin. These are the options with their required and optional parameters:
* upload : returns Pastebin URL
    -  –s secret
    -  –dk dev pastebin key
    -  –k AES key
    -  –m optional path to a cover text. If not provided, Lorem ipsum will be used
       
* download : returns secret 
    -  –u Pastebin_URL
    -  –k AES_key 
       
* hide : writes stegotext to destination file
  -    –s secret
  -    –d path to destination file
  -    –k AES key
  -    –m optional cover text. If not provided, Lorem ipsum will be used
       
* extract : reads stegotext and outputs secret
  -    –o path to input file
  -    –k AES key

# How to obtain dev and user pastebin keys
please, follow the instructions in the following link: https://pastebin.com/doc_api#1

# Authors
This tool has been created by the following super-hackers:
* [Hugo Ramon Pascual](https://github.com/datagames1)
* Jaime González Ruiz ( a.k.a XuLoJ) 
* Xabier (a.k.a Xabi)
* [JBalanza](https://github.com/JBalanza)