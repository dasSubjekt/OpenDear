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
            Features = 30, SignatureTarget = 31, EmbeddedSignature = 32, Fingerprint = 33
        }

        protected nSubpacketType _eType;

        #region constructors

        protected PgpSignatureSubpacket() : base()
        {
            _eType = nSubpacketType.Reserved;
        }

        protected PgpSignatureSubpacket(PgpSignatureSubpacket FromPacket)
        {
            _eType = FromPacket.eType;
            _eStatus = FromPacket.eStatus;
            _iHeaderLength = FromPacket.iHeaderLength;
            _iDataLength = FromPacket.iDataLength;
            _abRawBytes = FromPacket.abRawBytes;
        }

        public PgpSignatureSubpacket(byte[] abPaketBytes, int iOffset) : this()
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

                    // Console.WriteLine("iDataLength=" + _iDataLength.ToString());
                }
            }
        }

        #endregion

        #region properties

        /*
        /// <summary>Up to 4 bytes (if present) interpreted as flag values.</summary>
        public int iFlags
        {
            get
            {
                int i, iLength, iReturn = 0;

                if ((_abRawBytes != null) && (_abRawBytes.Length > _iHeaderLength))
                {
                    iLength = _abRawBytes.Length < _iHeaderLength + 5 ? _abRawBytes.Length : _iHeaderLength + 4;

                    // because of the flexible length we cannot use BitConverter.ToInt32(_abRawBytes, _iHeaderLength);
                    for (i = _iHeaderLength; i < iLength; i++)
                        iReturn |= (_abRawBytes[i] & 0xff) << (i << 3);
                }
                return iReturn;
            }

            // set
            // {
            //     byte[] abTemp = new byte[4];
            //     int i, iLength = 0;
            // 
            //     for (int i = 0; i < 4; i++)
            //     {
            //         abTemp[i] = (byte)(value >> (i * 8));
            //         if (abTemp[i] != 0)
            //             iLength = i;
            //     }
            // 
            //     _abRawBytes = new byte[iLength + 1];
            //     for (i = 0; i < iLength; i++)
            //         _abRawBytes[i] = abTemp[i];
            // }
        }
        */

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
