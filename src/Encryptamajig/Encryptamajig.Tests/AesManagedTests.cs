namespace Encryptamajig.Tests
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;
    using NUnit.Framework;

    [TestFixture]
    public class AesManagedTests
    {
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
