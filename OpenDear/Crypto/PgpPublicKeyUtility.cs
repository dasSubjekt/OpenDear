namespace OpenDear.Crypto
{
    using System;

    /// <summary>Helper class for PgpPublicKey and PgpPrivateKey to read and write the public key.</summary>
    public class PgpPublicKeyUtility : PgpPacket
    {
        private const byte cbAllowedVersion = 4;
        private const int ciModulusOffset = 8;   // offset of RSA public modulus within the packet


        private int _iModulusBits, _iExponentBits;
        private DateTime _Created;
        private nPublicKeyAlgorithm _ePublicKeyAlgorithm;
        private byte[] _abModulus, _abExponent;


        #region constructors

        public PgpPublicKeyUtility(byte[] abPacketBytes) : base(abPacketBytes, 0)
        {
            byte bVersion;
            int iModulusBytes, iModulusOffset, iExponentBytes, iExponentOffset;

            _iModulusBits = _iExponentBits = 0;
            _Created = DateTime.UtcNow;
            _ePublicKeyAlgorithm = nPublicKeyAlgorithm.RsaEncryptOrSign;
            _abModulus = _abExponent = null;

            if (_eStatus == PgpPacketBase.nStatus.OK)
            {
                iModulusOffset = _iHeaderLength + ciModulusOffset;

                if ((_abRawBytes == null) || (_abRawBytes.Length < iModulusOffset) || ((_ePacketTag != nPacketTag.PublicKey) && (_ePacketTag != nPacketTag.PublicSubkey) && (_ePacketTag != nPacketTag.PrivateKey) && (_ePacketTag != nPacketTag.PrivateSubkey)))
                {
                    _eStatus = nStatus.ParseError;
                }
                else if (_eStatus == nStatus.OK)
                {
                    bVersion = _abRawBytes[_iHeaderLength];

                    if (bVersion == cbAllowedVersion)
                    {
                        _Created = GetDateAt(_iHeaderLength + 1);
                        _ePublicKeyAlgorithm = (nPublicKeyAlgorithm)_abRawBytes[_iHeaderLength + 5];

                        if ((_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaEncryptOrSign) || (_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaEncryptOnly) || (_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaSignOnly))
                        {
                            _iModulusBits = _abRawBytes[iModulusOffset - 2] << 8 | _abRawBytes[iModulusOffset - 1];
                            iModulusBytes = (_iModulusBits + 7) >> 3;
                            iExponentOffset = iModulusOffset + iModulusBytes + 2;

                            if ((_abRawBytes.Length < iExponentOffset) || (_Created.Year < 1970) || (_Created.Year > DateTime.Now.Year))
                            {
                                _eStatus = nStatus.ParseError;
                            }
                            else
                            {
                                _iExponentBits = _abRawBytes[iExponentOffset - 2] << 8 | _abRawBytes[iExponentOffset - 1];
                                iExponentBytes = (_iExponentBits + 7) >> 3;

                                if ((((_ePacketTag == nPacketTag.PublicKey) || (_ePacketTag == nPacketTag.PublicSubkey)) && (_abRawBytes.Length == iExponentOffset + iExponentBytes)) ||
                                    (((_ePacketTag == nPacketTag.PrivateKey) || (_ePacketTag == nPacketTag.PrivateSubkey)) && (_abRawBytes.Length > iExponentOffset + iExponentBytes)))
                                {
                                    _abModulus = CopyFromRawBytes(iModulusOffset, iModulusBytes);
                                    _abExponent = CopyFromRawBytes(iExponentOffset, iExponentBytes);

                                    if (_abRawBytes.Length > iExponentOffset + iExponentBytes)
                                        EncodeRawBytes();   // re-encode to truncate the raw bytes to only the public key
                                }
                                else
                                    _eStatus = nStatus.ParseError;
                            }
                        }
                        else
                            _eStatus = nStatus.AlgorithmNotSupported;
                    }
                    else
                        _eStatus = nStatus.VersionNotSupported;
                }
            }
        }

        public PgpPublicKeyUtility(nPacketTag ePacketTag, DateTime Created, nPublicKeyAlgorithm ePublicKeyAlgorithm, byte[] abModulus, byte[] abExponent) : base(ePacketTag)
        {
            _eStatus = nStatus.OK;
            _Created = Created;
            _ePublicKeyAlgorithm = ePublicKeyAlgorithm;
            _iModulusBits = CountUsedBits(abModulus);
            _iExponentBits = CountUsedBits(abExponent);
            _abModulus = abModulus;
            _abExponent = abExponent;
            EncodeRawBytes();
        }

        #endregion

        #region properties

        public DateTime Created
        {
            get { return _Created; }
        }

        public byte[] abExponent
        {
            get { return _abExponent; }
        }

        public int iExponentBits
        {
            get { return _iExponentBits; }
        }

        public byte[] abModulus
        {
            get { return _abModulus; }
        }

        public int iModulusBits
        {
            get { return _iModulusBits; }
        }

        public nPublicKeyAlgorithm ePublicKeyAlgorithm
        {
            get { return _ePublicKeyAlgorithm; }
        }

        #endregion

        #region methods

        public override void EncodeRawBytes()
        {
            byte[] abHeader;

            if (_ePacketTag == nPacketTag.PrivateKey)
                _ePacketTag = nPacketTag.PublicKey;
            else if (_ePacketTag == nPacketTag.PrivateSubkey)
                _ePacketTag = nPacketTag.PublicSubkey;

            abHeader = EncodeHeaderBytes(ciModulusOffset + _abModulus.Length + 2 + _abExponent.Length);

            if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + _iDataLength))
                _abRawBytes = new byte[_iHeaderLength + _iDataLength];

            CopyToRawBytes(abHeader, 0, 0, _iHeaderLength);
            _abRawBytes[_iHeaderLength] = cbAllowedVersion;
            SetDateAt(_iHeaderLength + 1, _Created);
            _abRawBytes[_iHeaderLength + 5] = (byte)_ePublicKeyAlgorithm;
            _abRawBytes[_iHeaderLength + 6] = (byte)((_iModulusBits >> 8) & 0xff);
            _abRawBytes[_iHeaderLength + 7] = (byte)(_iModulusBits & 0xff);
            CopyToRawBytes(_abModulus, 0, _iHeaderLength + ciModulusOffset, _abModulus.Length);
            _abRawBytes[_iHeaderLength + ciModulusOffset + _abModulus.Length] = (byte)((_iExponentBits >> 8) & 0xff);
            _abRawBytes[_iHeaderLength + ciModulusOffset + _abModulus.Length + 1] = (byte)(_iExponentBits & 0xff);
            CopyToRawBytes(_abExponent, 0, _iHeaderLength + ciModulusOffset + _abModulus.Length + 2, _abExponent.Length);

            // Console.Write("PgpPublicKeyUtility.EncodeRawBytes=");
            // for (int i = 0; i < _abRawBytes.Length; i++)
            //     Console.Write(_abRawBytes[i].ToString("x2") + " ");
            // Console.WriteLine();
        }
        #endregion
    }
}
