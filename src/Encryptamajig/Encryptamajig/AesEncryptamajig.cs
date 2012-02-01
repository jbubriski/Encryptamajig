namespace Encryptamajig
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    /// A simple wrapper to the AesManaged class and the AES algorithm.
    /// To create a new Key and IV simple "new up" an AesManaged object and grab the Key and IV from that.
    /// Make sure to save the Key and IV if you want to decrypt your data later!
    /// </summary>
    public class AesEncryptamajig
    {
        // Remove the static salt and incorporate an easy method for managing it.
        private static readonly byte[] _salt = new byte[] { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 };

        /// <summary>
        /// Encrypts the plainText input using the given Key and IV.
        /// You can generate Keys and IV's from the GetKey() and GetIv() methods.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Encrypt(string plainText, string key, string iv, string salt)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");
            if (string.IsNullOrEmpty(iv))
                throw new ArgumentNullException("iv");
            if (string.IsNullOrEmpty(salt))
                throw new ArgumentNullException("salt");

            // TODO: Convert the salt to a byte array
            var saltBytes = new byte[0];

            using (var aesManaged = new AesManaged())
            using (var deriveBytes = new Rfc2898DeriveBytes(key, saltBytes))
            {
                // Derive the Key and the IV using Rfc2898DeriveBytes to make sure we get the same values given the same inputs
                var keyBytes = deriveBytes.GetBytes(aesManaged.KeySize);
                var ivBytes = deriveBytes.GetBytes(aesManaged.BlockSize);

                // Create an encryptor to perform the stream transform.
                var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes);

                // Create the streams used for encryption.
                using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                    streamWriter.Write(plainText);

                    // Return the encrypted bytes from the memory stream, in Base64 form so we can send it right to a database (if we want).
                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
        }

        /// <summary>
        /// Decrypts the cipherText using the Key and the IV.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, string key, string iv, string salt)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");
            if (string.IsNullOrEmpty(iv))
                throw new ArgumentNullException("iv");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("salt");

            // TODO: Convert the salt to a byte array
            var saltBytes = new byte[0];

            using (var aesManaged = new AesManaged())
            using (var deriveBytes = new Rfc2898DeriveBytes(key, saltBytes))
            {
                // Derive the Key and the IV using Rfc2898DeriveBytes to make sure we get the same values given the same inputs
                var keyBytes = deriveBytes.GetBytes(aesManaged.KeySize);
                var ivBytes = deriveBytes.GetBytes(aesManaged.BlockSize);

                // Create a decrytor to perform the stream transform.
                var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes);

                // Create the streams used for decryption.
                using (var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    return streamReader.ReadToEnd();
                }
            }
        }

        /// <summary>
        /// This will convert the plain text key to a byte array for use with the Encrypt/Decrypt methods.
        /// Make sure you are storing the plain text key in a secure location.
        /// For example, if you store the encryption key in the web.config, make sure you encrypt the web.config.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] GetKey(string key)
        {
            var deriveBytes = new Rfc2898DeriveBytes(key, _salt);

            return deriveBytes.GetBytes(32);
        }

        /// <summary>
        /// This will generate an IV (Intialization Vector) based on the input text. The same input text will generate the same IV.
        /// The same IV is required to decrypt the data, so make sure the input text is being saved with the encrypted data.
        /// Don't use the same IV input text for all your data.
        /// For example, if you're encrypting user records, use this method to generate the IV from the user's username.
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        private static byte[] GetIv(string text)
        {
            var deriveBytes = new Rfc2898DeriveBytes(text, _salt);

            return deriveBytes.GetBytes(16);
        }

    }
}