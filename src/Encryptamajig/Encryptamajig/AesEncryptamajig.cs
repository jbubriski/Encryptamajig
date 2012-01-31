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
        private static readonly byte[] _salt = new byte[] { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 };

        /// <summary>
        /// This will convert the plain text key to a byte array for use with the Encrypt/Decrypt methods.
        /// Make sure you are storing the plain text key in a secure location.
        /// For example, if you store the encryption key in the web.config, make sure you encrypt the web.config.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] GetKey(string key)
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
        public static byte[] GetIv(string text)
        {
            var deriveBytes = new Rfc2898DeriveBytes(text, _salt);

            return deriveBytes.GetBytes(16);
        }

        /// <summary>
        /// Encrypts the plainText input using the given Key and IV.
        /// You can generate Keys and IV's from the GetKey() and GetIv() methods.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Encrypt(string plainText, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            MemoryStream memoryStream = null;
            RijndaelManaged aesAlg = null;

            try
            {
                // Create the encryption algorithm object with the specified key and IV.
                aesAlg = new RijndaelManaged();

                // Create an encryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(key, iv);

                // Create the streams used for encryption.
                memoryStream = new MemoryStream();

                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    //Write all data to the stream.
                    streamWriter.Write(plainText);
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(memoryStream.ToArray());
        }

        /// <summary>
        /// Decrypts the cipherText using the Key and the IV.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            RijndaelManaged aesAlg = null;
            string plaintext = null;

            try
            {
                // Create a the encryption algorithm object with the specified key and IV.
                aesAlg = new RijndaelManaged();

                // Create a decrytor to perform the stream transform.
                var decryptor = aesAlg.CreateDecryptor(key, iv);

                // Create the streams used for decryption.
                using (var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Read the decrypted bytes from the decrypting stream
                    // and place them in a string.
                    plaintext = streamReader.ReadToEnd();
                }
            }
            finally
            {
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plaintext;
        }
    }
}