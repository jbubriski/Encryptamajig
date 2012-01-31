namespace Encryptamajig.Tests
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;
    using NUnit.Framework;

    [TestFixture]
    public class EncryptamajigTests
    {
        private readonly string _plainText = "Some text to encrypt";
        private readonly string _key = "Some key to use for encrypting data";
        private readonly string _userName1 = "UserName 1";
        private readonly string _userName2 = "UserName 2";

        [Test]
        public void AesManaged_EncryptionRoundtripWithRandomInputs_ReturnsOriginalText()
        {
            // Arrange
            var aesManaged = new AesManaged();

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, aesManaged.Key, aesManaged.IV);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, aesManaged.Key, aesManaged.IV);

            Debug.WriteLine(_plainText);
            Debug.WriteLine(encrypted);
            Debug.WriteLine(roundtrip);

            // Assert
            Assert.AreNotEqual(_plainText, encrypted);
            Assert.AreEqual(_plainText, roundtrip);
        }

        [Test]
        public void AesManaged_EncryptionRoundtripWithCustomInputs_ReturnsOriginalText()
        {
            // Arrange
            var key = AesEncryptamajig.GetKey(_key);
            var iv = AesEncryptamajig.GetIv(_userName1);

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, key, iv);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, key, iv);

            Debug.WriteLine(_plainText);
            Debug.WriteLine(encrypted);
            Debug.WriteLine(roundtrip);

            // Assert
            Assert.AreNotEqual(_plainText, encrypted);
            Assert.AreEqual(_plainText, roundtrip);
        }

        [Test]
        public void AesManaged_ReencryptionWithSameKeyAndIv_ReturnsSameText()
        {
            // Arrange
            var aesManaged = new AesManaged();

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, aesManaged.Key, aesManaged.IV);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, aesManaged.Key, aesManaged.IV);

            Debug.WriteLine(_plainText);
            Debug.WriteLine(encrypted);
            Debug.WriteLine(roundtrip);

            // Act 2 (encrypt the same data again)
            encrypted = AesEncryptamajig.Encrypt(_plainText, aesManaged.Key, aesManaged.IV);
            roundtrip = AesEncryptamajig.Decrypt(encrypted, aesManaged.Key, aesManaged.IV);

            // Assert
            Assert.AreNotEqual(_plainText, encrypted);
            Assert.AreEqual(_plainText, roundtrip);
        }

        [Test]
        [ExpectedException(ExpectedException = typeof(CryptographicException))]
        public void Decrypt_WithDifferentKey_ThrowsException()
        {
            // Arrange
            var aesManaged = new AesManaged();

            var originalKey = aesManaged.Key;
            var originalIv = aesManaged.IV;

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, originalKey, originalIv);

            // This should generate a new key
            aesManaged = new AesManaged();

            Debug.WriteLine("Org Key = " + Convert.ToBase64String(originalKey));
            Debug.WriteLine("New Key = " + Convert.ToBase64String(aesManaged.Key));

            string roundtrip = AesEncryptamajig.Decrypt(encrypted, aesManaged.Key, originalIv);

            // Assert
            throw new Exception("This should have thrown a CryptographicException!");
        }

        [Test]
        public void Decrypt_WithDifferentIv_ReturnsDifferentResult()
        {
            // Arrange
            var aesManaged = new AesManaged();

            var originalKey = aesManaged.Key;
            var originalIv = aesManaged.IV;

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, originalKey, originalIv);

            // This should generate a new key
            aesManaged = new AesManaged();

            var roundtrip = AesEncryptamajig.Decrypt(encrypted, originalKey, aesManaged.IV);

            // Assert
            Debug.WriteLine("Org IV: " + Convert.ToBase64String(originalIv));
            Debug.WriteLine("New IV: " + Convert.ToBase64String(aesManaged.IV));

            Debug.WriteLine(_plainText);
            Debug.WriteLine("Encrypted: " + encrypted);
            Debug.WriteLine("ROundtrup: " + roundtrip);

            Assert.AreNotEqual(_plainText, roundtrip);
        }

        [Test]
        public void GetKey_GetIvToo_KeyAndIvAreDifferent()
        {
            var key = AesEncryptamajig.GetKey(_key);
            var iv = AesEncryptamajig.GetIv(_userName1);

            Console.WriteLine(Convert.ToBase64String(key));
            Console.WriteLine(Convert.ToBase64String(iv));

            Assert.AreNotEqual(key, iv);
        }

        [Test]
        public void GetKey_CalledTwice_KeyIsTheSame()
        {
            var keybytes = AesEncryptamajig.GetKey(_key);
            var keyBytesAgain = AesEncryptamajig.GetKey(_key);

            Console.WriteLine(Convert.ToBase64String(keybytes));
            Console.WriteLine(Convert.ToBase64String(keyBytesAgain));

            Assert.AreEqual(keybytes, keyBytesAgain);
        }

        [Test]
        public void GetIv_CalledTwice_IvIsTheSame()
        {
            var ivbytes = AesEncryptamajig.GetIv(_userName1);
            var ivbytesAgain = AesEncryptamajig.GetIv(_userName1);

            Console.WriteLine(Convert.ToBase64String(ivbytes));
            Console.WriteLine(Convert.ToBase64String(ivbytesAgain));

            Assert.AreEqual(ivbytes, ivbytesAgain);
        }

        [Test]
        public void GetKey_CalledWithPlainTextKey_GeneratesValidKeySize()
        {
            // Arrange
            var aesManaged = new AesManaged();

            // Act
            var key = AesEncryptamajig.GetKey(_key);

            // Assert
            Assert.That(aesManaged.ValidKeySize(key.Length * 8));
        }

        [Test]
        public void GetIv_CalledWIthUserName_GeneratesValidIvSize()
        {
            // Arrange
            var aesManaged = new AesManaged();

            // Act
            var iv = AesEncryptamajig.GetIv(_userName1);

            // Assert
            Assert.That(aesManaged.BlockSize == (iv.Length * 8));
        }

        [Test]
        public void GetIv_SameInputs_GeneratesSameIvs()
        {
            // Arrange
            // Act
            var iv1 = AesEncryptamajig.GetIv(_userName1);
            var iv2 = AesEncryptamajig.GetIv(_userName1);

            // Assert
            Assert.AreEqual(iv1, iv2);
        }

        [Test]
        public void GetIv_DifferentInputs_GeneratesDifferentIvs()
        {
            // Arrange
            // Act
            var iv1 = AesEncryptamajig.GetIv(_userName1);
            var iv2 = AesEncryptamajig.GetIv(_userName2);

            // Assert
            Assert.AreNotEqual(iv1, iv2);
        }

        [Test]
        public void AesManaged_NewInstances_ReturnsNewKeyAndIv()
        {
            // Arrange
            // Act
            var aesManaged = new AesManaged();
            var aesManaged2 = new AesManaged();

            Debug.WriteLine(Convert.ToBase64String(aesManaged.Key));
            Debug.WriteLine(Convert.ToBase64String(aesManaged2.Key));

            Debug.WriteLine(Convert.ToBase64String(aesManaged.IV));
            Debug.WriteLine(Convert.ToBase64String(aesManaged2.IV));

            // Assert
            Assert.AreNotEqual(aesManaged.Key, aesManaged2.Key);
            Assert.AreNotEqual(aesManaged.IV, aesManaged2.IV);
        }
    }
}