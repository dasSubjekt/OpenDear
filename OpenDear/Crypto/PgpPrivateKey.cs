namespace OpenDear.Crypto
{
    using System;
    using System.Security.Cryptography;


    /// <summary>Implements RFC 4880 section 5.5.3. Secret-Key Packet Formats.</summary>
    public class PgpPrivateKey : PgpPacket
    {
        private const int ciCodedCountMax = 0xff;
        private const int ciParameterBitsMin = 1000;
        private const int ciParameterBitsMax = 0x4000;

        private int _iDBits, _iPBits, _iQBits, _iInverseQBits, _iOffsetSecretKey;
        private nStringToKeyUsage _eStringToKeyUsage;
        private nSymmetricKeyAlgorithm _eSymmetricKeyAlgorithm;
        private nStringToKeySpecifier _eStringToKeySpecifier;
        private nHashAlgorithm _eHashAlgorithm;
        private EncryptionServices _Cryptography;
        private PgpPublicKey _PublicKey;
        private RSAParameters _KeyParameters;

        #region constructors

        /// <summary></summary>
        public PgpPrivateKey(PgpPacket FromPacket, EncryptionServices Cryptography) : base(FromPacket)
        {
            PgpPublicKeyUtility KeyUtility;

            Initialise();

            _Cryptography = Cryptography;
            KeyUtility = new PgpPublicKeyUtility(_abRawBytes);   // extract the public key bytes
            _eStatus = KeyUtility.eStatus;

            if (_eStatus == nStatus.OK)
            {
                _PublicKey = new PgpPublicKey(new PgpPacket(KeyUtility.abRawBytes, 0));   // and turn them into a public key
                _KeyParameters.Exponent = KeyUtility.abExponent;
                _KeyParameters.Modulus = KeyUtility.abModulus;
                _eStatus = _PublicKey.eStatus;

                if (_eStatus == nStatus.OK)
                {
                    _iOffsetSecretKey = _PublicKey.iHeaderLength + _PublicKey.iDataLength;
                    _eStringToKeyUsage = (nStringToKeyUsage)_abRawBytes[_iOffsetSecretKey++];

                    if ((_eStringToKeyUsage == nStringToKeyUsage.Sha1) || (_eStringToKeyUsage == nStringToKeyUsage.Checksum))
                    {
                        _eSymmetricKeyAlgorithm = (nSymmetricKeyAlgorithm)_abRawBytes[_iOffsetSecretKey++];
                        _eStringToKeySpecifier = (nStringToKeySpecifier)_abRawBytes[_iOffsetSecretKey++];
                        _eHashAlgorithm = (nHashAlgorithm)_abRawBytes[_iOffsetSecretKey++];

                        if ((_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Unencrypted) || (_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Aes128))
                        {
                            if (_eStringToKeySpecifier == nStringToKeySpecifier.GnuDummy)
                                throw new NotImplementedException("eStringToKeySpecifier == nStringToKeySpecifier.GnuDummy");
                        }
                        else
                            _eStatus = nStatus.AlgorithmNotSupported;
                    }
                    else
                        _eStatus = nStatus.AlgorithmNotSupported;
                }
            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public nHashAlgorithm eHashAlgorithm
        {
            get { return _eHashAlgorithm; }
        }

        public RSAParameters KeyParameters
        {
            get { return _KeyParameters; }
        }

        /// <summary></summary>
        public PgpPublicKey PublicKey
        {
            get { return _PublicKey; }
        }

        /// <summary></summary>
        public nStringToKeySpecifier eStringToKeySpecifier
        {
            get { return _eStringToKeySpecifier; }
        }

        /// <summary></summary>
        public nStringToKeyUsage eStringToKeyUsage
        {
            get { return _eStringToKeyUsage; }
        }

        /// <summary></summary>
        public nSymmetricKeyAlgorithm eSymmetricKeyAlgorithm
        {
            get { return _eSymmetricKeyAlgorithm; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        private int GetParameter(byte[] abSource, int iSourceOffset, ref byte[] abParameter)
        {
            int iBits, iBytes, iReturn = 0;

            if ((abSource != null) && (iSourceOffset >= 0))
            {
                iBits = abSource[iSourceOffset] << 8 | abSource[iSourceOffset + 1];
                iSourceOffset += 2;
                iBytes = (iBits + 7) >> 3;

                if ((iBits >= ciParameterBitsMin) && (iBits <= ciParameterBitsMax) && (iSourceOffset + iBytes <= abSource.Length))
                {
                    abParameter = CopyBytes(abSource, iSourceOffset, iBytes);
                    iReturn = iBits;
                }
            }
            return iReturn;
        }

        /// <summary></summary>
        private void Initialise()
        {
            _iDBits = _iPBits = _iQBits = _iInverseQBits = _iOffsetSecretKey = 0;
            _eStringToKeyUsage = nStringToKeyUsage.Sha1;
            _eSymmetricKeyAlgorithm = nSymmetricKeyAlgorithm.Aes128;
            _eStringToKeySpecifier = nStringToKeySpecifier.SaltedAndIterated;
            _eHashAlgorithm = nHashAlgorithm.Sha1;
            _Cryptography = null;
            _PublicKey = null;
            _KeyParameters = new RSAParameters();
        }

        /// <summary></summary>
        public void Lock()
        {
            Overwrite(ref _KeyParameters.D);
            Overwrite(ref _KeyParameters.P);
            Overwrite(ref _KeyParameters.Q);
            Overwrite(ref _KeyParameters.InverseQ);
        }

        /// <summary></summary>
        private void Overwrite(ref byte[] abBytes)
        {
            if (abBytes != null)
            {
                _Cryptography.GetRandomBytes(abBytes);
                abBytes = null;
            }
        }

        /// <summary></summary>
        private byte[] StringToKey(byte[] abPassword, byte[] abSalt, int iCountDecoded)
        {
            int i, j;
            int iLen2 = abPassword.Length + abSalt.Length;
            int iCount = iLen2 < iCountDecoded ? iCountDecoded : iLen2;
            byte[] abHash, abHashBuffer = new byte[iCountDecoded];

            i = 0;
            while (iCount > iLen2)
            {
                for (j = 0; j < abSalt.Length; j++)
                    abHashBuffer[i++] = abSalt[j];
                for (j = 0; j < abPassword.Length; j++)
                    abHashBuffer[i++] = abPassword[j];
                iCount -= iLen2;
            }

            if (iCount < abSalt.Length)
            {
                for (j = 0; j < iCount; j++)
                    abHashBuffer[i++] = abSalt[j];
            }
            else
            {
                for (j = 0; j < abSalt.Length; j++)
                    abHashBuffer[i++] = abSalt[j];
                iCount -= abSalt.Length;
                for (j = 0; j < iCount; j++)
                    abHashBuffer[i++] = abPassword[j];
            }

            abHash = _Cryptography.ComputeHash(abHashBuffer, HashAlgorithmName.SHA1);

            return CopyBytes(abHash, 0, EncryptionServices.ciAesBlockLength);
        }

        /// <summary>Unlocks this private key with the passphrase and decrypts its secret data.</summary>
        public bool Unlock(byte[] abPassphrase)
        {
            bool isHashVerified, isReturn = false;
            int i, iCodedCount, iCountDecoded, iEncryptedLength, iOffset = _iOffsetSecretKey;
            byte[] abAesKey, abEncrypted, abDecrypted, abHash, abHashData, abInitialisationVector, abSalt;
            PgpAesWithCfb PgpAes;

            if ((_eStringToKeySpecifier == nStringToKeySpecifier.Salted) || (_eStringToKeySpecifier == nStringToKeySpecifier.SaltedAndIterated))
            {
                abSalt = CopyBytes(_abRawBytes, iOffset, ciSaltLength);
                iOffset += ciSaltLength;
            }
            else
                abSalt = null;

            if (_eStringToKeySpecifier == nStringToKeySpecifier.SaltedAndIterated)
            {
                iCodedCount = _abRawBytes[iOffset++];
                iCountDecoded = (16 + (iCodedCount & 15)) << ((iCodedCount >> 4) + 6);
            }
            else
                iCountDecoded = 0;

            if (_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Aes128)
            {
                abInitialisationVector = CopyBytes(_abRawBytes, iOffset, EncryptionServices.ciAesBlockLength);
                iOffset += EncryptionServices.ciAesBlockLength;

                iEncryptedLength = _abRawBytes.Length - iOffset;
                abEncrypted = CopyBytes(_abRawBytes, iOffset, iEncryptedLength);

                abAesKey = StringToKey(abPassphrase, abSalt, iCountDecoded);
                PgpAes = new PgpAesWithCfb(abAesKey, abInitialisationVector, _Cryptography);
                abDecrypted = PgpAes.Decrypt(abEncrypted);
                PgpAes.Dispose();   // overwrite the AES key and other temporary data

                // Console.Write("abDecrypted=");
                // for (i = 0; i < abDecrypted.Length; i++)
                //     Console.Write(abDecrypted[i].ToString("x2") + " ");
                // Console.WriteLine();

                abHashData = new byte[iEncryptedLength - 20];
                for (i = 0; i < abHashData.Length; i++)
                    abHashData[i] = abDecrypted[i];

                abHash = new byte[ciSha1FingerprintLength];
                for (i = 0; i < ciSha1FingerprintLength; i++)
                    abHash[i] = abDecrypted[iEncryptedLength - ciSha1FingerprintLength + i];

                isHashVerified = _Cryptography.VerifyHash(abHashData, abHash, HashAlgorithmName.SHA1);

                if (isHashVerified)
                {
                    iOffset = 0;

                    _iDBits = GetParameter(abDecrypted, iOffset, ref _KeyParameters.D);
                    Console.WriteLine("iDBits=" + _iDBits.ToString());
                    iOffset += _KeyParameters.D.Length + 2;

                    _iPBits = GetParameter(abDecrypted, iOffset, ref _KeyParameters.P);
                    Console.WriteLine("iPBits=" + _iPBits.ToString());
                    iOffset += _KeyParameters.P.Length + 2;

                    _iQBits = GetParameter(abDecrypted, iOffset, ref _KeyParameters.Q);
                    Console.WriteLine("iQBits=" + _iQBits.ToString());
                    iOffset += _KeyParameters.Q.Length + 2;

                    _iInverseQBits = GetParameter(abDecrypted, iOffset, ref _KeyParameters.InverseQ);
                    Console.WriteLine("iInverseQBits=" + _iInverseQBits.ToString());
                    iOffset += _KeyParameters.InverseQ.Length + 2;

                    if ((iEncryptedLength - iOffset == ciSha1FingerprintLength) && (_iDBits > 0) && (_iPBits > 0) && (_iQBits > 0) && (_iInverseQBits > 0))
                    {
                        // TODO test: p and q must be primes and cannot be equal, RocaVulnerability

                        _eStatus = nStatus.OK;
                        isReturn = true;
                    }
                    else
                        _eStatus = nStatus.ParseError;
                }
                else
                    _eStatus = nStatus.DecryptionFailed;

                Overwrite(ref abDecrypted);   // overwrite the decrypted secret key bytes in working memory
            }
            else
                _eStatus = nStatus.AlgorithmNotSupported;

            Overwrite(ref abPassphrase);   // overwrite the plaintext password in working memory
            return isReturn;
        }

        #endregion
    }
}
