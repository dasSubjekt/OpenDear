namespace OpenDear.Crypto
{
    using System;
    using OpenDear.Model;


    public class PgpFingerprint : PgpSignatureSubpacket, IEquatable<PgpFingerprint>
    {
        private const byte cbAllowedVersion = 4;
        private const int ciLengthInBytes = 20;

        private readonly byte[] _abFingerprint;

        #region constructors

        public PgpFingerprint(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            _abFingerprint = null;

            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + ciLengthInBytes + 2))
                {
                    _eStatus = nStatus.ParseError;
                }
                else if (_abRawBytes[_iHeaderLength + 1] != cbAllowedVersion)
                {
                    _eStatus = nStatus.VersionNotSupported;
                }
                else
                {
                    _abFingerprint = CopyFromRawBytes(_iHeaderLength + 2, ciLengthInBytes);
                }
            }
        }

        #endregion

        #region operators

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator ==(PgpFingerprint First, PgpFingerprint Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return Equals(First, Second);
            else
                return First.Equals(Second);
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator !=(PgpFingerprint First, PgpFingerprint Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return !Equals(First, Second);
            else
                return !(First.Equals(Second));
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abFingerprint
        {
            get { return _abFingerprint; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        /// <param name=""></param>
        public bool Equals(PgpFingerprint Other)
        {
            BytesAndTextUtility Bytes = new BytesAndTextUtility(_abFingerprint, Other.abFingerprint);

            return (Other != null) && (_eType == Other.eType) && Bytes.isAllBytesEqual;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public override bool Equals(object Other)
        {
            if (Other == null)
                return false;
            else
            {
                PgpFingerprint OtherFingerprint = Other as PgpFingerprint;
                if (OtherFingerprint == null)
                    return false;
                else
                    return Equals(OtherFingerprint);
            }
        }

        /// <summary></summary>
        public override int GetHashCode()
        {
            return _abFingerprint.GetHashCode();
        }

        /// <summary></summary>
        public override string ToString()
        {
            BytesAndTextUtility Bytes = new BytesAndTextUtility(_abFingerprint);

            return Bytes.sHexadecimalBytes;
        }
        #endregion
    }
}
