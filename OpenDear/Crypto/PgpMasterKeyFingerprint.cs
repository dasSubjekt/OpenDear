namespace OpenDear.Crypto
{
    using System;


    public class PgpMasterKeyFingerprint : PgpSignatureSubpacket
    {
        private const byte cbAllowedVersion = 4;


        private readonly byte[] _abFingerprint;

        #region constructors

        public PgpMasterKeyFingerprint(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            _abFingerprint = null;

            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + ciSha1FingerprintLength + 2))
                {
                    _eStatus = nStatus.ParseError;
                }
                else if (_abRawBytes[_iHeaderLength + 1] != cbAllowedVersion)
                {
                    _eStatus = nStatus.VersionNotSupported;
                }
                else
                {
                    _abFingerprint = CopyFromRawBytes(_iHeaderLength + 2, ciSha1FingerprintLength);
                }
            }
        }

        #endregion

        #region properties

        /// <summary>SHA-1 hash of the public key packet, see RFC 4880 section 12.2. Key IDs and Fingerprints</summary>
        public byte[] abFingerprint
        {
            get { return _abFingerprint; }
        }

        #endregion

        #region methods        

        /// <summary></summary>
        public override int GetHashCode()
        {
            return _abFingerprint.GetHashCode();
        }

        #endregion
    }
}
