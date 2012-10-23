namespace Encryptamajig
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// A simple wrapper to the AesManaged class and the AES algorithm.
    /// Requires a securely stored key which should be a random string of characters that an attacker could never guess.
    /// Make sure to save the Key if you want to decrypt your data later!
    /// If you're using this with a Web app, put the key in the web.config and encrypt the web.config.
    /// </summary>
    public class AesEncryptamajig
    {
        private static readonly int SaltSize = 32;

        public static string Encrypt(string clearText, byte[] key)
        {
            return Encrypt(clearText, Convert.ToBase64String(key));
        }

        /// <summary>
        /// Encrypts the plainText input using the given Key.
        /// A 128 bit random salt will be generated and prepended to the ciphertext before it is base64 encoded.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The salt and the ciphertext, Base64 encoded for convenience.</returns>
        public static string Encrypt(string plainText, string key)
        {
            Validate(plainText, "plainText");
            Validate(key, "key");
        
            // Derive a new Salt and IV from the Key
            var bytes = DeriveBytes(key);

            // Return the encrypted bytes from the memory stream, in Base64 form so we can send it right to a database.
            var cipherTextBytes = EncryptStream(plainText, bytes);
            var array = AddSalt(bytes.Salt, cipherTextBytes);
            return Convert.ToBase64String(array);

            // var cipherTextBytes = memoryStream.ToArray();
            // Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
            // Array.Copy(cipherTextBytes, 0, saltBytes, _saltSize, cipherTextBytes.Length);

        }

        public static string Decrypt(string cipher, byte[] key)
        {
            return Decrypt(cipher, Convert.ToBase64String(key));
        }

        /// <summary>
        /// Decrypts the ciphertext using the Key.
        /// </summary>
        /// <param name="cipherText">The cipher text to decrypt.</param>
        /// <param name="key">The plain text encryption key.</param>
        /// <returns>The decrypted text.</returns>
         public static string Decrypt(string cipherText, string key)
         {
            Validate(cipherText, "cipherText");
            Validate(key, "key");

            // Extract the salt from our ciphertext
            var allTheBytes = Convert.FromBase64String(cipherText);
            var saltBytes = allTheBytes.Take(SaltSize).ToArray();
            var ciphertextBytes = allTheBytes.Skip(SaltSize).Take(allTheBytes.Length - SaltSize).ToArray();
            
            var keys = DeriveBytes(key, saltBytes);

            return DecryptStream(ciphertextBytes, keys);
        }

        private static void Validate(string field, string fieldName)
        {
            if (string.IsNullOrEmpty(field))
            {
                throw new ArgumentNullException(fieldName);
            }
        }

        private static byte[] AddSalt(byte[] salt, byte[] cipher)
        {
            var array = salt;
            Array.Resize(ref array, salt.Length + cipher.Length);
            Array.Copy(cipher, 0, array, SaltSize, cipher.Length);
            return array;
        }

        private static DeriveResult DeriveBytes(string key)
        {
            using (var deriver = new Rfc2898DeriveBytes(key, SaltSize))
            {
                return new DeriveResult
                    {
                        Salt = deriver.Salt,
                        Key = deriver.GetBytes(32),
                        InitializationVector = deriver.GetBytes(16)
                    };
            }
        }

        private static DeriveResult DeriveBytes(string key, byte[] salt)
        {
            using (var deriver = new Rfc2898DeriveBytes(key, salt))
            {
                // Derive the previous IV from the Key and Salt
                return new DeriveResult
                    {
                        Salt = deriver.Salt,
                        Key = deriver.GetBytes(32),
                        InitializationVector = deriver.GetBytes(16)
                    };
            }
        }

        private static byte[] EncryptStream(string plainText, DeriveResult keys)
        {
            // Create an encryptor to perform the stream transform.
            // Create the streams used for encryption. (Yes, we have 5 levels of IDisposable here!)
            using (var aesManaged = new AesManaged())
            using (var encryptor = aesManaged.CreateEncryptor(keys.Key, keys.InitializationVector))
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            using (var streamWriter = new StreamWriter(cryptoStream))
            {
                // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                streamWriter.Write(plainText);
                var cipherTextBytes = memoryStream.ToArray();
                return cipherTextBytes;
            }
        }

        private static string DecryptStream(byte[] cipher, DeriveResult keys)
        {
            // Create a decrytor to perform the stream transform.
            // Create the streams used for decryption.
            // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
            using (var aesManaged = new AesManaged())
            using (var decryptor = aesManaged.CreateDecryptor(keys.Key, keys.InitializationVector))
            using (var memoryStream = new MemoryStream(cipher))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptoStream))
            {
                // Return the decrypted bytes from the decrypting stream.
                return streamReader.ReadToEnd();
            }
        }
    }
}