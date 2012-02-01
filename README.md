# Encryptamajig

A simple wrapper to the .NET AES encryption algorithm functionality.

**(Note: this is not a new encryption alogorithm, it's simply a wrapper that forces you to use AES as correctly.)**

## But Why?

> **"But John, there are so many encryption examples on the 'Net, why do we need another?  Can't I just role my own?"**

When you look at encryption examples online many are verbose, misleading, outdated, or **flat out insecure**.  By creating this project I hope to provide a single resource that myself and others can use to incoporate encryption into their .NET projects.

My goal is to make sure this project uses an up-to-date encryption algorithm and forces appropriate usage of that algorithm.

## Who Should Use This

Anyone needing to encrypt data using a good algorithm that doesn't want to screw it up.

## Issues We Avoid
 
 - Use of the ECB cipher mode.  Simply put, ECB is unsecure.  If you don't believe me, look at the images in this [Wikipedia article on the various cipher modes](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation).
 - Use of older or less secure algorithms. (Right now this is more of an assumption, I will try and cite specific algorithms to avoid and update this readme)
 - Incorrect usage of encryption algorithms and block cipher modes.
 - Guess work.  Which algorithm do I use, how do I use it, what size should my key be, what size should my IV be, do I need a salt, etc.
 - Use of the Rijndael algorithm.  While Rijndael is a good algorithm, it's the **predecessor** to AES. So why not use AES?  Read these articles if you more reasons or if you don't believe me: [The Differences Between Rijndael and AES](http://blogs.msdn.com/b/shawnfa/archive/2006/10/09/the-differences-between-rijndael-and-aes.aspx) and [the MSDN documentation for Rijndael](http://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndael(v=vs.90).aspx).
 - Ugly code.  This code is tight.

## Usage

The AesEncryptamajig class provides 2 methods: 1 for encrypting and 1 for decrypting.  You call both methods with your plain text key, and the data that you want to encrypt/decrypt.  After encrypting data for the first time using this library, the salt will be prepended to the ciphertext.  When you decrypt the data using this library, the salt is extracted, and the IV (Initialization Vector) is recreated.  This way, you don't have to worry about storing the Salt/IV separately.

Make sure you are storing your key someplace safe.  If you're writing a web appication, you can store the Key in the Web.Config, **but make sure you encrypt the Web.Config**.

## Encryption Resources

Do you want to know more? (All links via Wikipedia)

- [Encryption](http://en.wikipedia.org/wiki/Encryption)
- [Keys](http://en.wikipedia.org/wiki/Key_(cryptography))
- [Initialization Vectors](http://en.wikipedia.org/wiki/Initialization_vector)
- [Block Cipher Modes](http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation)
- [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## Disclaimer

I am not a security expert but I think I got the big things right.  **If you are an expert** and you see that I'm doing something wrong, please tell me!  I will take the time to look at your pull requests if you send one!

"You don't know what you don't know", or more like "I don't know what I don't know".