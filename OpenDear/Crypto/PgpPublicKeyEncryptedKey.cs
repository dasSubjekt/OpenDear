namespace OpenDear.Crypto
{
    using System;


    /// <summary>Implements RFC 4880 section 5.1. Public-Key Encrypted Session Key Packets.</summary>
    public class PgpPublicKeyEncryptedKey : PgpPacket
    {
        /// <summary>Only version 3 Public-Key Encrypted Session Key Packets are implemented, see RFC 4880 section 5.1.</summary>
        private const byte cbAllowedVersion = 3;

        /// <summary>Version number + key id (8 bytes) + public-key algorithm + encrypted session key length (2 bytes) = 12 bytes, see RFC 4880 section 5.1.</summary>
        private const int ciEncryptedKeyHeaderLength = 12;


        #region constructors

        private byte[] _abEncryptedKey, _abPublicKeyId;
        private int _iEncryptedKeyBits;
        private string _sUserId;
        private nPublicKeyAlgorithm _ePublicKeyAlgorithm;
        private PgpSignature _MatchedPublicKey;


        public PgpPublicKeyEncryptedKey(PgpPacket FromPacket) : base(FromPacket)
        {
            _abEncryptedKey = _abPublicKeyId = null;
            _iEncryptedKeyBits = 0;
            _sUserId = string.Empty;
            _ePublicKeyAlgorithm = nPublicKeyAlgorithm.RsaEncryptOrSign;
            _MatchedPublicKey = null;
            Parse();
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abEncryptedKey
        {
            get { return _abEncryptedKey; }
        }

        public int iEncryptedKeyBits
        {
            get { return _iEncryptedKeyBits; }
        }

        public PgpSignature MatchedPublicKey
        {
            get { return _MatchedPublicKey; }
            set { _MatchedPublicKey = value; }
        }

        /// <summary></summary>
        public nPublicKeyAlgorithm ePublicKeyAlgorithm
        {
            get { return _ePublicKeyAlgorithm; }
        }

        /// <summary></summary>
        public byte[] abPublicKeyId
        {
            get { return _abPublicKeyId; }
        }

        /// <summary></summary>
        public string sUserId
        {
            get { return _sUserId; }
            set { _sUserId = value; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        public void Parse()
        {
            byte bVersion;
            int i, iEncryptedKeyBytes;

            if ((_abRawBytes == null) || (_abRawBytes.Length < _iHeaderLength + ciEncryptedKeyHeaderLength) || (_ePacketTag != nPacketTag.PublicKeyEncryptedKey))
            {
                _eStatus = nStatus.ParseError;
            }
            else if (_eStatus == nStatus.OK)
            {
                bVersion = _abRawBytes[_iHeaderLength];

                if (bVersion == cbAllowedVersion)
                {
                    _abPublicKeyId = new Byte[ciKeyIdLength];
                    for (i = 0; i < ciKeyIdLength; i++)
                        _abPublicKeyId[i] = _abRawBytes[_iHeaderLength + 1 + i];

                    _ePublicKeyAlgorithm = (nPublicKeyAlgorithm)_abRawBytes[_iHeaderLength + 9];

                    if ((_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaEncryptOrSign) || (_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaEncryptOnly))
                    {
                        _iEncryptedKeyBits = (_abRawBytes[_iHeaderLength + 10] << 8) | _abRawBytes[_iHeaderLength + 11];
                        iEncryptedKeyBytes = (_iEncryptedKeyBits + 7) >> 3;

                        if (_abRawBytes.Length == _iHeaderLength + ciEncryptedKeyHeaderLength + iEncryptedKeyBytes)
                        {
                            _abEncryptedKey = new byte[iEncryptedKeyBytes];
                            for (i = 0; i < iEncryptedKeyBytes; i++)
                                _abEncryptedKey[i] = _abRawBytes[_iHeaderLength + ciEncryptedKeyHeaderLength + i];
                        }
                        else
                            _eStatus = nStatus.ParseError;
                    }
                    else
                        _eStatus = nStatus.AlgorithmNotSupported;
                }
                else
                    _eStatus = nStatus.VersionNotSupported;
            }
            // else keep the value of _eStatus from PgpPacketBase
        }

        #endregion
    }
}
