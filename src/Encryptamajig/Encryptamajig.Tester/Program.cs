namespace Encryptamajig.Tester
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Diagnostics;

    class Program
    {
        // A test credit card number
        private static readonly string _plainText = "4111111111111111";

        // The key should be a random string of characters that an attacker could never guess
        private static readonly string _key = "Something you can't guess";

        static void Main(string[] args)
        {
            var encrypted = AesEncryptamajig.Encrypt(_plainText, _key);
            var roundtrip = AesEncryptamajig.Decrypt(encrypted, _key);

            Debug.WriteLine(_plainText);
            Debug.WriteLine(encrypted);
            Debug.WriteLine(roundtrip);
        }
    }
}
