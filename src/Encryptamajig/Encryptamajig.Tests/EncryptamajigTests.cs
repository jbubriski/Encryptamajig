namespace Encryptamajig.Tests
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;
    using NUnit.Framework;

    [TestFixture]
    public class EncryptamajigTests
    {
        // A test credit card number
        private static readonly string _plainText = "4111111111111111";

        // The key should be a random string of characters that an attacker could never guess
        private static readonly string _key = "Something you can't guess";

        [Test]
        public void AesManaged_EncryptionRoundtripWithRandomKey_ReturnsOriginalText()
        {
            // Arrange
            var aesManaged = new AesManaged();

            var key = Convert.ToBase64String(aesManaged.Key);

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, key);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, key);

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
            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, _key);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, _key);

            Debug.WriteLine(_plainText);
            Debug.WriteLine(encrypted);
            Debug.WriteLine(roundtrip);

            // Assert
            Assert.AreNotEqual(_plainText, encrypted);
            Assert.AreEqual(_plainText, roundtrip);
        }

        [Test]
        public void AesManaged_ReencryptionWithSameKey_ReturnsSameText()
        {
            // Arrange
            var aesManaged = new AesManaged();

            var key = Convert.ToBase64String(aesManaged.Key);

            // Act
            var encrypted1 = AesEncryptamajig.Encrypt(_plainText, key);
            var roundtrip1 = AesEncryptamajig.Decrypt(encrypted1, key);

            Debug.WriteLine("Plain Text: " + _plainText);
            Debug.WriteLine("Encrypted: " + encrypted1);
            Debug.WriteLine("Roundtrip: " + roundtrip1);

            // Act 2 (encrypt the same data again)
            var encrypted2 = AesEncryptamajig.Encrypt(_plainText, key);
            var roundtrip2 = AesEncryptamajig.Decrypt(encrypted2, key);


            Debug.WriteLine("Encrypted again: " + encrypted2);
            Debug.WriteLine("Roundtrip again: " + roundtrip2);

            // Assert
            Assert.AreNotEqual(_plainText, encrypted1);
            Assert.AreNotEqual(_plainText, encrypted2);

            Assert.AreEqual(_plainText, roundtrip1);
            Assert.AreEqual(_plainText, roundtrip2);

            Assert.AreNotEqual(encrypted1, encrypted2);
        }

        [Test]
        [ExpectedException(ExpectedException = typeof(CryptographicException))]
        public void Decrypt_WithDifferentKey_ThrowsException()
        {
            // Arrange
            var aesManaged = new AesManaged();

            var originalKey = Convert.ToBase64String(aesManaged.Key);

            // This should generate a new key
            aesManaged = new AesManaged();
            var newKey = Convert.ToBase64String(aesManaged.Key);

            // Act
            var encrypted = AesEncryptamajig.Encrypt(_plainText, originalKey);

            Debug.WriteLine("Org Key = " + originalKey);
            Debug.WriteLine("New Key = " + newKey);

            string roundtrip = AesEncryptamajig.Decrypt(encrypted, newKey);

            // Assert
            throw new Exception("This should have thrown a CryptographicException!");
        }
    }
}