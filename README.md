# Encryptamajig

A simple wrapper to the .NET AES encryption algorithm functionality.

**(Note: this is not a new encryption alogorithm, simply a wrapper to one of the good ones.)**

## But Why?

> **"There are so many encryption examples on the 'Net, why do we need another one John?  Can't I just role my own?"**

When you look at encryption examples online many are verbose, outdated, or **flat out insecure**.  By creating this project I hope to provide a single resource that myself and others can use to incoporate encryption into their .NET projects.

My goal is to make sure this project uses an up-to-date encryption algorithm and encourages (and maybe forces) appropriate usage of that algorithm.

## Issues We Avoid
 
 - Use of the ECB cipher mode.  Simply put, ECB is unsecure.  If you don't believe me, look at the images in this [Wikipedia article on the various cipher modes](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation).
 - Use of older or less secure algorithms. (Right now this is more of an assumption, I will try and cite specific algorithms to avoid and update this readme)
 - Incorrect usage.
 - Guess work.  Which algorithm do I use, how do I use it, etc.
 - Use of the Rijndael algorithm.  While Rijndael is a good algorithm, it's the **predecessor** to AES. So why not use AES?  Read these articles if you more reasons or if you don't believe me: [The Differences Between Rijndael and AES](http://blogs.msdn.com/b/shawnfa/archive/2006/10/09/the-differences-between-rijndael-and-aes.aspx) and [the MSDN documentation for Rijndael](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndael(v=vs.90).aspx).
 - Ugly code.

## Usage

The AesEncryptamajig class provides 2 methods: 1 for encrypting and 1 for decrypting.  You call both methods with a Key and IV (Initialization Vector), and the data that you want to encrypt/decrypt.

If you need a new key and IV, simply new up the AesManaged class from the BCL (Base Class Library), and grab the Key and IV from that instance.  **Every time you create a new instance of the AesManaged class, you get a new key and IV.**  Make sure you are storing them somewhere if you want to decrypt your data!

## Encryption Resources

Do you want to know more?

- [Encryption](http://en.wikipedia.org/wiki/Encryption)
- [Keys](http://en.wikipedia.org/wiki/Key_(cryptography))
- [Initialization Vectors](http://en.wikipedia.org/wiki/Initialization_vector)
- [Block Cipher Modes](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation)
- [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## Disclaimer

I am not a security expert but I think I got the big things right.  **If you are an expert** and you see that I'm doing something wrong, please tell me!

"You don't know what you don't know", or more like "I don't know what I don't know".