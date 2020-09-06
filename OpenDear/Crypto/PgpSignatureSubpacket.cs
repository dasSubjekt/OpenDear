namespace OpenDear.Crypto
{
    using System;


    public class PgpSignatureSubpacket : PgpPacketBase
    {
        /// <remarks>RFC 4880 section 5.2.3.1. Signature Subpacket Specification.</remarks>
        public enum nSubpacketType
        {
            Reserved = 0, CreationTime = 2, ExpirationTime = 3, Exportable = 4, Trust = 5, RegularExpression = 6, Revocable = 7,
            KeyExpireTime = 9, Placeholder = 10, PreferredSymmetricAlgorithms = 11, RevocationKey = 12, IssuerKeyId = 16,
            NotationData = 20, PreferredHashAlgorithms = 21, PreferredCompressionAlgorithms = 22, KeyServerPreferences = 23,
            PreferredKeyServer = 24, PrimaryUserId = 25, PolicyUri = 26, KeyFlags = 27, SignerUserId = 28, RevocationReason = 29,
            Features = 30, SignatureTarget = 31, EmbeddedSignature = 32, MasterKeyFingerprint = 33
        }

        protected nSubpacketType _eType;

        #region constructors

        protected PgpSignatureSubpacket(nSubpacketType eType) : base()
        {
            _eType = eType;
        }

        protected PgpSignatureSubpacket(PgpSignatureSubpacket FromPacket)
        {
            _eType = FromPacket.eType;
            _eStatus = FromPacket.eStatus;
            _iHeaderLength = FromPacket.iHeaderLength;
            _iDataLength = FromPacket.iDataLength;
            _abRawBytes = FromPacket.abRawBytes;
        }

        public PgpSignatureSubpacket(byte[] abPaketBytes, int iOffset) : this(nSubpacketType.Reserved)
        {
            byte bLengthByte, bPacketTag;
            int i;

            if ((abPaketBytes == null) || (iOffset >= abPaketBytes.Length - 2))
            {
                _eStatus = nStatus.ParseError;
            }
            else
            {
                _eStatus = nStatus.OK;
                bLengthByte = abPaketBytes[iOffset];

                if (bLengthByte < cbSmallestTwoByteLengthNew)
                {
                    _iDataLength = bLengthByte;
                    _iHeaderLength = 1;
                }
                else if (bLengthByte < 0xe0)
                {
                    _iDataLength = ((bLengthByte - cbSmallestTwoByteLengthNew) << 8) + abPaketBytes[iOffset + 1] + cbSmallestTwoByteLengthNew;
                    _iHeaderLength = 2;
                }
                else if (bLengthByte == 0xff)
                {
                    _iDataLength = abPaketBytes[iOffset + 1] << 24 | abPaketBytes[iOffset + 2] << 16 | abPaketBytes[iOffset + 3] << 8 | abPaketBytes[iOffset + 4];
                    _iHeaderLength = 5;
                }
                else
                    _eStatus = nStatus.ParseError;


                if (_eStatus == nStatus.OK)
                {
                    bPacketTag = abPaketBytes[iOffset + _iHeaderLength];
                    _eType = (nSubpacketType)(bPacketTag & 0x7f);

                    _abRawBytes = new byte[_iHeaderLength + _iDataLength];
                    for (i = 0; i < _iHeaderLength + _iDataLength; i++)
                        _abRawBytes[i] = abPaketBytes[iOffset + i];
                }
            }
        }

        #endregion

        #region properties

        /// <summary>Subpacket type.</summary>
        public nSubpacketType eType
        {
            get { return _eType; }
        }

        #endregion

        #region methods

        #endregion
    }
}
