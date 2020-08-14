namespace OpenDear.Crypto
{
    using System;
    using System.Text;
    using System.Security.Cryptography;
    using System.IO;

    // using Org.BouncyCastle.Crypto.Modes;
    // using Org.BouncyCastle.Crypto.Engines;
    // using Org.BouncyCastle.Crypto.Parameters;


    /// <summary>Implements RFC 4880 section 5.5.3. Secret-Key Packet Formats.</summary>
    public class PgpPrivateKey : PgpPacket
    {
        private const int ciSha1Length = 20;

        private int _iDBits, _iPBits, _iQBits, _iInverseQBits;
        private nStringToKeyUsage _eStringToKeyUsage;
        private nSymmetricKeyAlgorithm _eSymmetricKeyAlgorithm;
        private nStringToKeySpecifier _eStringToKeySpecifier;
        private nHashAlgorithm _eHashAlgorithm;
        private EncryptionServices _Cryptography;
        private PgpPublicKey _PublicKey;
        private RSAParameters _KeyParameters;

        #region constructors

        public PgpPrivateKey(PgpPacket FromPacket, EncryptionServices Cryptography) : base(FromPacket)
        {
            bool isHashVerified;
            int i, iCount, iCountDecoded, iEncryptedLength, iOffsetDecrypted, iOffsetSecretKey;
            byte[] abEncrypted, abDecrypted, abHash, abHashData, abInitialisationVector, abReEncrypted, abSalt;
            PgpPublicKeyUtility KeyUtility;

            Initialise();

            _Cryptography = Cryptography;
            KeyUtility = new PgpPublicKeyUtility(_abRawBytes);   // extract the public key bytes
            _eStatus = KeyUtility.eStatus;

            if (_eStatus == nStatus.OK)
            {
                _PublicKey = new PgpPublicKey(new PgpPacket(KeyUtility.abRawBytes, 0));   // and turn them into a public key
                _eStatus = _PublicKey.eStatus;

                if (_eStatus == nStatus.OK)
                {
                    iOffsetSecretKey = _PublicKey.iHeaderLength + _PublicKey.iDataLength;
                    _eStringToKeyUsage = (nStringToKeyUsage)_abRawBytes[iOffsetSecretKey++];

                    if ((_eStringToKeyUsage == nStringToKeyUsage.Sha1) || (_eStringToKeyUsage == nStringToKeyUsage.Checksum))
                    {
                        _eSymmetricKeyAlgorithm = (nSymmetricKeyAlgorithm)_abRawBytes[iOffsetSecretKey++];
                        _eStringToKeySpecifier = (nStringToKeySpecifier)_abRawBytes[iOffsetSecretKey++];
                        _eHashAlgorithm = (nHashAlgorithm)_abRawBytes[iOffsetSecretKey++];

                        Console.WriteLine("eStringToKeyUsage=" + _eStringToKeyUsage.ToString());
                        Console.WriteLine("eSymmetricKeyAlgorithm=" + _eSymmetricKeyAlgorithm.ToString());
                        Console.WriteLine("eStringToKeySpecifier=" + _eStringToKeySpecifier.ToString());
                        Console.WriteLine("eHashAlgorithm=" + _eHashAlgorithm.ToString());

                        if ((_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Unencrypted) || (_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Aes128))
                        {
                            if (_eStringToKeySpecifier == nStringToKeySpecifier.GnuDummy)
                            {
                                // abCopiedBytes = new byte[3];
                                // iComputedPacketLength += 3;
                                // for (i = 0; i < 3; i++)
                                //     abCopiedBytes[i] = abKeyFile[iPacketPointer + iComputedPacketLength + i + 1];
                                // 
                                // iComputedPacketLength++;
                                // iS2kMode = abKeyFile[iPacketPointer + iComputedPacketLength + 3];
                                throw new NotImplementedException("eStringToKeySpecifier == nStringToKeySpecifier.GnuDummy");
                            }

                            if ((_eStringToKeySpecifier == nStringToKeySpecifier.Salted) || (_eStringToKeySpecifier == nStringToKeySpecifier.SaltedAndIterated))
                            {
                                abSalt = new byte[8];
                                Console.Write("Salt=");
                                for (i = 0; i < 8; i++)
                                {
                                    abSalt[i] = _abRawBytes[iOffsetSecretKey++];
                                    Console.Write(abSalt[i].ToString("x2") + " ");
                                }
                                Console.WriteLine();
                            }
                            else
                                abSalt = null;

                            if (_eStringToKeySpecifier == nStringToKeySpecifier.SaltedAndIterated)
                            {
                                iCount = _abRawBytes[iOffsetSecretKey++];
                                Console.WriteLine("iCount=0x" + iCount.ToString("x2"));
                                iCountDecoded = (16 + (iCount & 15)) << ((iCount >> 4) + 6);
                                Console.WriteLine("iCountDecoded=" + iCountDecoded.ToString());
                            }
                            else
                                iCountDecoded = 0;

                            if (_eSymmetricKeyAlgorithm == nSymmetricKeyAlgorithm.Aes128)
                            {
                                abInitialisationVector = new byte[16];
                                Console.Write("abInitialisationVector=");
                                for (i = 0; i < 16; i++)
                                {
                                    abInitialisationVector[i] = _abRawBytes[iOffsetSecretKey++];
                                    Console.Write(abInitialisationVector[i].ToString("x2") + " ");
                                }
                                Console.WriteLine();

                                iEncryptedLength = _abRawBytes.Length - iOffsetSecretKey;
                                Console.WriteLine("iEncryptedLength=" + iEncryptedLength.ToString());

                                /*
                                byte[] k = StringToKey(Encoding.UTF8.GetBytes("a"), abSalt, iCountDecoded);
                                Console.Write("Key = ");
                                for (i = 0; i < k.Length; i++)
                                    Console.Write(k[i].ToString("x2") + " ");

                                Console.WriteLine();

                                abEncrypted = new byte[iEncryptedLength];
                                Console.Write("abEncrypted=");
                                for (i = 0; i < iEncryptedLength; i++)
                                {
                                    abEncrypted[i] = _abRawBytes[iOffsetSecretKey++];
                                    Console.Write(abEncrypted[i].ToString("x2") + " ");
                                }
                                Console.WriteLine();

                                PgpAesWithCfb aes = new PgpAesWithCfb(k, abInitialisationVector, _Cryptography);
                                abDecrypted = aes.Decrypt(abEncrypted);

                                Console.Write("abDecrypted=");
                                for (i = 0; i < abDecrypted.Length; i++)
                                    Console.Write(abDecrypted[i].ToString("x2") + " ");
                                Console.WriteLine();

                                aes.Reset(k, abInitialisationVector);
                                abReEncrypted = aes.Encrypt(abDecrypted);
                                aes.Dispose();

                                Console.Write("abReEncrypted=");
                                for (i = 0; i < abReEncrypted.Length; i++)
                                    Console.Write(abReEncrypted[i].ToString("x2") + " ");
                                Console.WriteLine();

                                abHashData = new byte[iEncryptedLength - 20];
                                for (i = 0; i < abHashData.Length; i++)
                                    abHashData[i] = abDecrypted[i];

                                abHash = new byte[ciSha1Length];
                                for (i = 0; i < ciSha1Length; i++)
                                    abHash[i] = abDecrypted[iEncryptedLength - 20 + i];

                                isHashVerified = _Cryptography.VerifyHash(abHashData, abHash, HashAlgorithmName.SHA1);
                                Console.WriteLine("isHashVerified=" + isHashVerified.ToString());

                                if (isHashVerified)
                                {
                                    iOffsetDecrypted = 0;

                                    _iDBits = GetParameter(abDecrypted, iOffsetDecrypted, ref _KeyParameters.D);
                                    Console.WriteLine("iDBits=" + _iDBits.ToString());
                                    iOffsetDecrypted += _KeyParameters.D.Length + 2;

                                    _iPBits = GetParameter(abDecrypted, iOffsetDecrypted, ref _KeyParameters.P);
                                    Console.WriteLine("iPBits=" + _iPBits.ToString());
                                    iOffsetDecrypted += _KeyParameters.P.Length + 2;

                                    _iQBits = GetParameter(abDecrypted, iOffsetDecrypted, ref _KeyParameters.Q);
                                    Console.WriteLine("iQBits=" + _iQBits.ToString());
                                    iOffsetDecrypted += _KeyParameters.Q.Length + 2;

                                    _iInverseQBits = GetParameter(abDecrypted, iOffsetDecrypted, ref _KeyParameters.InverseQ);
                                    Console.WriteLine("iInverseQBits=" + _iInverseQBits.ToString());
                                    iOffsetDecrypted += _KeyParameters.InverseQ.Length + 2;

                                    if ((_iDBits == 0) || (_iPBits == 0) || (_iQBits == 0) || (_iInverseQBits == 0))
                                        _eStatus = nStatus.ParseError;

                                    Console.Write((iEncryptedLength - iOffsetDecrypted).ToString() + " bytes left: ");
                                    for (i = iOffsetDecrypted; i < iEncryptedLength; i++)
                                        Console.Write(abDecrypted[i].ToString("x2") + " ");
                                    Console.WriteLine();                                   
                                }
                                else
                                    _eStatus = nStatus.DecryptionFailed;
                                */
                            }
                        }
                        else
                            _eStatus = nStatus.AlgorithmNotSupported;
                    }
                    else
                        _eStatus = nStatus.AlgorithmNotSupported;
                }
            }

            // TODO test: p and q must be primes and cannot be equal, RocaVulnerability
        }

        #endregion

        #region properties

        public PgpPublicKey PublicKey
        {
            get { return _PublicKey; }
        }

        #endregion

        #region methods

        private int GetParameter(byte[] abSource, int iSourceOffset, ref byte[] abParameter)
        {
            int iBits, iBytes, iReturn = 0;

            if ((abSource != null) && (iSourceOffset >= 0))
            {
                iBits = abSource[iSourceOffset] << 8 | abSource[iSourceOffset + 1];
                iSourceOffset += 2;
                iBytes = (iBits + 7) >> 3;

                if ((iBits > 1000) && (iBits <= 16384) && (iSourceOffset + iBytes <= abSource.Length))
                {
                    abParameter = CopyBytes(abSource, iSourceOffset, iBytes);
                    iReturn = iBits;
                }
            }
            return iReturn;
        }

        private void Initialise()
        {
            _iDBits = _iPBits = _iQBits = _iInverseQBits = 0;
            _eStringToKeyUsage = nStringToKeyUsage.Sha1;
            _eSymmetricKeyAlgorithm = nSymmetricKeyAlgorithm.Aes128;
            _eStringToKeySpecifier = nStringToKeySpecifier.SaltedAndIterated;
            _eHashAlgorithm = nHashAlgorithm.Sha1;
            _Cryptography = null;
            _PublicKey = null;
            _KeyParameters = new RSAParameters();
        }

        public void Lock()
        {

        }

        private byte[] StringToKey(byte[] abPassword, byte[] abSalt, int iCountDecoded)
        {
            int i, j;
            int iLen2 = abPassword.Length + abSalt.Length;
            int iCount = iLen2 < iCountDecoded ? iCountDecoded : iLen2;
            byte[] abReturn, abHash, abHashBuffer = new byte[iCountDecoded];

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
            abReturn = new byte[16];
            for (i = 0; i < 16; i++)
                abReturn[i] = abHash[i];

            return abReturn;
        }

        public bool Unlock(byte[] abPassword)
        {
            bool isReturn = false;

            return isReturn;
        }

        #endregion
    }
}
