﻿namespace OpenDear.Crypto
{
    using System;


    /// <summary>Based on <see href="https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/modes/CfbBlockCipher.cs">Bouncy Castle Cipher-FeedBack mode</see>.</summary>
    public class PgpAesWithCfb
    {
        private byte[] _abCfbInputVector, _abCfbOutputVector, _abInitialisationVector, _abKey;
        private EncryptionServices _Cryptography;


        #region constructors

        public PgpAesWithCfb(byte[] abKey, byte[] abInitialisationVector, EncryptionServices Cryptography)
        {
            _abCfbInputVector = _abCfbOutputVector = null;
            _Cryptography = Cryptography;
            Reset(abKey, abInitialisationVector);
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abInitialisationVector
        {
            get { return _abInitialisationVector; }
        }

        /// <summary></summary>
        public byte[] abKey
        {
            get { return _abKey; }
        }

        #endregion

        #region methods

        private void CFB(byte[] abInputBuffer, byte[] abOutputBuffer, int iOffset, bool isEncrypting)
        {
            int i;

            if (isEncrypting)
            {
                // XOR the CFB with the plaintext producing the ciphertext and copy the input block
                for (i = 0; i < EncryptionServices.ciAesBlockLength; i++)
                    _abCfbInputVector[i] = abOutputBuffer[iOffset + i] = (byte)(_abCfbOutputVector[i] ^ abInputBuffer[iOffset + i]);
            }
            else
            {
                // copy the input block and XOR the CFB with the ciphertext producing the plaintext
                for (i = 0; i < EncryptionServices.ciAesBlockLength; i++)
                {
                    _abCfbInputVector[i] = abInputBuffer[iOffset + i];
                    abOutputBuffer[iOffset + i] = (byte)(_abCfbOutputVector[i] ^ abInputBuffer[iOffset + i]);
                }
            }
        }

        public byte[] Decrypt(byte[] abCipher)
        {
            return Process(abCipher, false);
        }

        /// <summary></summary>
        public void Dispose()
        {
            if (_abCfbInputVector != null)
            {
                _Cryptography.GetRandomBytes(_abCfbInputVector);
                _abCfbInputVector = null;
            }
            if (_abCfbOutputVector != null)
            {
                _Cryptography.GetRandomBytes(_abCfbOutputVector);
                _abCfbOutputVector = null;
            }
            if (_abInitialisationVector != null)
            {
                _Cryptography.GetRandomBytes(_abInitialisationVector);
                _abInitialisationVector = null;
            }
            if (_abKey != null)
            {
                _Cryptography.GetRandomBytes(_abKey);
                _abKey = null;
            }
        }

        public byte[] Encrypt(byte[] abPlain)
        {
            return Process(abPlain, true);
        }

        private void Overwrite(byte[] abData)
        {
            if (abData != null)
            {
                for (int i = 0; i < abData.Length; i++)
                    abData[i] = 0;
            }
        }

        private byte[] Process(byte[] abInputBuffer, bool isEncrypting)
        {
            int i, iLength, iOffset = 0;
            byte[] abLastInputBuffer, abLastOutputBuffer, abReturn = null;

            if (abInputBuffer != null)
            {
                abReturn = new byte[abInputBuffer.Length];

                while (iOffset < abInputBuffer.Length)
                {
                    Overwrite(_abCfbOutputVector);
                    _abCfbOutputVector = _Cryptography.EncryptAesBlock(_abCfbInputVector);

                    if (abInputBuffer.Length < iOffset + EncryptionServices.ciAesBlockLength)
                    {
                        iLength = abInputBuffer.Length - iOffset;
                        abLastInputBuffer = new byte[EncryptionServices.ciAesBlockLength];
                        abLastOutputBuffer = new byte[EncryptionServices.ciAesBlockLength];

                        for (i = 0; i < EncryptionServices.ciAesBlockLength; i++)
                            abLastInputBuffer[i] = (i < iLength) ? abInputBuffer[iOffset + i] : (byte)0;

                        CFB(abLastInputBuffer, abLastOutputBuffer, 0, isEncrypting);

                        for (i = 0; i < iLength; i++)
                            abReturn[iOffset + i] = abLastOutputBuffer[i];
                    }
                    else
                        CFB(abInputBuffer, abReturn, iOffset, isEncrypting);

                    iOffset += EncryptionServices.ciAesBlockLength;
                }
            }
            return abReturn;
        }

        public void Reset(byte[] abKey, byte[] abInitialisationVector)
        {
            if ((abKey == null) || ((abKey.Length != EncryptionServices.ciKeySize128) && (abKey.Length != EncryptionServices.ciKeySize192) && (abKey.Length != EncryptionServices.ciKeySize256)))
            {
                throw new ArgumentException("Invalid key size in PgpAesWithCfb().");
            }
            else if ((abInitialisationVector == null) || (abInitialisationVector.Length != EncryptionServices.ciAesBlockLength))
            {
                throw new ArgumentException("Invalid initialisation vector in PgpAesWithCfb().");
            }
            else
            {
                _abKey = abKey;
                _abInitialisationVector = abInitialisationVector;

                if (_abCfbInputVector == null)
                    _abCfbInputVector = new byte[EncryptionServices.ciAesBlockLength];

                if (_abCfbOutputVector != null)
                {
                    _Cryptography.GetRandomBytes(_abCfbOutputVector);
                    _abCfbOutputVector = null;
                }

                for (int i = 0; i < EncryptionServices.ciAesBlockLength; i++)
                    _abCfbInputVector[i] = _abInitialisationVector[i];

                _Cryptography.InitialiseEncryptAesBlocks(abKey);
            }
        }
        #endregion

    }
}
