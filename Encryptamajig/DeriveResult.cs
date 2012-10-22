namespace Encryptamajig
{
    /// <summary>
    /// Holds the result of derivation functions, including salt and key/iv pair.
    /// </summary>
    internal struct DeriveResult
    {
        public byte[] Salt { get; set; }

        public byte[] Key { get; set; }

        public byte[] InitializationVector { get; set; }
    }
}
