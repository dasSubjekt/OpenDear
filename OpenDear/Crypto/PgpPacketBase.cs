namespace OpenDear.Crypto
{
    using System;


    public class PgpPacketBase
    {
        protected const byte cbSmallestTwoByteLengthNew = 0xc0;

        /// <summary>1 January 1970 UTC, see RFC 4880 section 3.5. Time Fields.</summary>
        protected const long ckSeconds_1_1_1970_Utc = 62135596800L;

        public enum nStatus { OK, AlgorithmNotSupported, DecryptionFailed, IndeterminateLengthNotSupported, InvalidPacketTag, MissingArgument, ParseError, SignatureNotVerified, Undefined, VersionNotSupported };

        /// <remarks>RFC 4880 section 3.7.1. String-to-Key (S2K) Specifier Types.</remarks>
        public enum nStringToKeySpecifier { Simple = 0, Salted = 1, SaltedAndIterated = 3, GnuDummy = 101 };

        /// <remarks>RFC 4880 section 5.2.1. Signature type codes.</remarks>
        public enum nSignatureType
        {
            Binary = 0, CanonicalText = 1, Standalone = 2, GenericCertification = 16, PersonalCertification = 17, CasualCertification = 18, PositiveCertification = 19,
            SubkeyBinding = 24, PrimaryKeyBinding = 25, Direct = 31, KeyRevocation = 32, SubkeyRevocation = 40, CertificationRevocation = 48, Timestamp = 64, ThirdPartyConfirmation = 80
        };

        /// <remarks>RFC 4880 section 5.2.3.23. Reason for revocation codes.</remarks>
        public enum nRevocationReason { NotSpecified = 0, KeySuperseded = 1, KeyCompromised = 2, KeyRetired = 3, UserNoLongerValid = 32 }

        /// <remarks>RFC 4880 section 5.5.3. Secret-Key Packet Formats.</remarks>
        public enum nStringToKeyUsage { None = 0, Sha1 = 254, Checksum = 255 };

        /// <remarks>RFC 4880 section 9.1. Public-key algorithm codes.</remarks>
        public enum nPublicKeyAlgorithm
        {
            RsaEncryptOrSign = 1, RsaEncryptOnly = 2, RsaSignOnly = 3, ElGamalEncryptOnly = 16, DigitalSignatureAlgorithm = 17, ECDH = 18, ECDSA = 19, ElGamalEncryptOrSign = 20, DiffieHellman = 21
        };

        /// <remarks>RFC 4880 section 9.2. Symmetric-key algorithm codes.</remarks>
        public enum nSymmetricKeyAlgorithm
        {
            Unencrypted = 0, Idea = 1, TripleDes = 2, Cast5 = 3, Blowfish = 4, SaferSk128 = 5, Des = 6, Aes128 = 7, Aes192 = 8, Aes256 = 9, Twofish = 10, Camellia128 = 11, Camellia192 = 12, Camellia256 = 13
        };

        /// <remarks>RFC 4880 section 9.3. Compression algorithm codes.</remarks>
        public enum nCompressionAlgorithm { Uncompressed = 0, Zip = 1, ZLib = 2, BZip2 = 3 };

        /// <remarks>RFC 4880 section 9.4. Hash algorithm codes.</remarks>
        public enum nHashAlgorithm { MD5 = 1, Sha1 = 2, RipeMD160 = 3, DoubleSha = 4, MD2 = 5, Tiger192 = 6, Haval5pass160 = 7, Sha256 = 8, Sha384 = 9, Sha512 = 10, Sha224 = 11 };


        protected nStatus _eStatus;
        protected int _iDataLength, _iHeaderLength;
        protected byte[] _abRawBytes;

        #region constructors

        protected PgpPacketBase()
        {
            _eStatus = nStatus.Undefined;
            _iDataLength = _iHeaderLength = 0;
            _abRawBytes = null;
        }

        protected PgpPacketBase(PgpPacketBase FromPacket)
        {
            _eStatus = FromPacket.eStatus;
            _iHeaderLength = FromPacket.iHeaderLength;
            _iDataLength = FromPacket.iDataLength;
            _abRawBytes = FromPacket.abRawBytes;
        }
        #endregion

        #region properties

        /// <summary>Number of data bytes, not including packet tag and packet length.</summary>
        public int iDataLength
        {
            get { return _iDataLength; }
        }

        /// <summary>Number of bytes used for packet tag (always one byte) and packet length.</summary>
        public int iHeaderLength
        {
            get { return _iHeaderLength; }
        }

        /// <summary>Complete memory representation of the OpenPGP packet, including packet tag and packet length.</summary>
        public byte[] abRawBytes
        {
            get { return _abRawBytes; }
        }

        /// <summary>Error code.</summary>
        public nStatus eStatus
        {
            get { return _eStatus; }
        }
        #endregion

        #region methods

        protected byte[] CopyBytes(byte[] abSource, int iSourceOffset, int iLength)
        {
            byte[] abReturn = null;

            if ((abSource != null) && (iSourceOffset >= 0) && (iLength >= 0) && (iSourceOffset + iLength <= abSource.Length))
            {
                abReturn = new byte[iLength];

                for (int i = 0; i < iLength; i++)
                    abReturn[i] = abSource[iSourceOffset + i];
            }
            return abReturn;
        }

        public byte[] CopyFromRawBytes(int iStart, int iLength)
        {
            byte[] abReturn = null;
            int i;

            if ((_abRawBytes != null) && (iStart >= 0) && (iLength >= 0) && (iStart + iLength <= _abRawBytes.Length))
            {
                abReturn = new byte[iLength];
                for (i = 0; i < iLength; i++)
                    abReturn[i] = _abRawBytes[iStart + i];
            }
            return abReturn;
        }

        public void CopyFromRawBytes(byte[] abDestination, int iDestinationOffset, int iRawBytesOffset, int iLength)
        {
            if ((_abRawBytes != null) && (abDestination != null) && (iDestinationOffset >= 0) && (iRawBytesOffset >= 0) && (iLength >= 0) && (iRawBytesOffset + iLength <= _abRawBytes.Length) && (iDestinationOffset + iLength <= abDestination.Length))
            {
                for (int i = 0; i < iLength; i++)
                {
                    abDestination[iDestinationOffset + i] = _abRawBytes[iRawBytesOffset + i];
                    Console.Write(_abRawBytes[iRawBytesOffset + i].ToString("x2") + " ");
                }
                Console.WriteLine();
            }
            else
                throw new ArgumentException("PgpPacketBase.CopyFromRawBytes()");
        }

        protected void CopyToRawBytes(uint uNumber, int iOffset)
        {
            if ((iOffset < 0) || (iOffset + 4 > _abRawBytes.Length))
                throw new ArgumentException("Offset out of range in PgpPacketBase.WriteToRawBytes().");
            else
            {
                _abRawBytes[iOffset] = (byte)((uNumber >> 24) & 0xff);
                _abRawBytes[iOffset + 1] = (byte)((uNumber >> 16) & 0xff);
                _abRawBytes[iOffset + 2] = (byte)((uNumber >> 8) & 0xff);
                _abRawBytes[iOffset + 3] = (byte)(uNumber & 0xff);
            }
        }

        protected void CopyToRawBytes(byte[] abSource, int iSourceOffset, int iRawBytesOffset, int iLength)
        {
            if ((_abRawBytes != null) && (abSource != null) && (iSourceOffset >= 0) && (iRawBytesOffset >= 0) && (iLength >= 0) && (iRawBytesOffset + iLength <= _abRawBytes.Length) && (iSourceOffset + iLength <= abSource.Length))
            {
                for (int i = 0; i < iLength; i++)
                    _abRawBytes[iRawBytesOffset + i] = abSource[iSourceOffset + i];
            }
            else
                throw new ArgumentException("PgpPacketBase.CopyToRawBytes()");
        }

        protected int CountUsedBits(byte[] abLongInteger)
        {
            int i, j, iReturn;
            byte b;

            if ((abLongInteger == null) || (abLongInteger.Length == 0))
            {
                _eStatus = nStatus.ParseError;
                iReturn = 0;
            }
            else
            {
                iReturn = abLongInteger.Length << 3;
                i = 0;
                do
                {
                    b = abLongInteger[i++];
                    if (b == 0)
                    {
                        iReturn -= 8;
                    }
                    else
                    {
                        j = 0;
                        do
                        {
                            if ((b & 0x80) == 0)
                            {
                                iReturn--;
                                b <<= 1;
                                j++;
                            }
                            else
                                j = 8;    // end the loop
                        } while (j < 8);
                        i = abLongInteger.Length;    // end the loop
                    }
                } while (i < abLongInteger.Length);
            }
            return iReturn;
        }

        public virtual void EncodeRawBytes()
        {
            throw new NotImplementedException("The method PgpPacketBase.EncodeRawBytes() must be overwritten in each derived class.");
        }

        /// <summary>Read date and time from abRawBytes.</summary>
        protected DateTime GetDateAt(int iOffset)
        {
            uint uSeconds;
            DateTime Return = DateTime.MinValue;

            if ((_abRawBytes != null) && (iOffset >= 0) && (iOffset + 4 <= _abRawBytes.Length))
            {
                uSeconds = ((uint)_abRawBytes[iOffset] << 24) | ((uint)_abRawBytes[iOffset + 1] << 16) | ((uint)_abRawBytes[iOffset + 2] << 8) | (uint)_abRawBytes[iOffset + 3];
                Return = new DateTime((ckSeconds_1_1_1970_Utc + uSeconds) * TimeSpan.TicksPerSecond);
            }
            return Return;
        }

        /// <summary>Write date and time to abRawBytes.</summary>
        protected void SetDateAt(int iOffset, DateTime Date)
        {
            uint uSeconds = (uint)(Date.Ticks / TimeSpan.TicksPerSecond - ckSeconds_1_1_1970_Utc);

            if (uSeconds < 0)
                throw new ArgumentException("DateTime value may not be before 1 January 1970 UTC.");
            else
                CopyToRawBytes(uSeconds, iOffset);
        }

        #endregion
    }
}
