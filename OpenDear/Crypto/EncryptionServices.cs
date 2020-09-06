namespace OpenDear.Crypto
{
    using System;
    using System.IO;
    using Microsoft.Win32;
    using Net.Pkcs11Interop.Common;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using Net.Pkcs11Interop.HighLevelAPI;


    /// <summary>All cryptography other than PGP, no keys stored here.</summary>
    public class EncryptionServices
    {
        public const int ciAesBlockLength = 16;         // 16 * 8 bits per byte = 128-bit, the only block size allowed for AES

        public const int ciAes256KeyBytesLength = 32;   // 32 * 8 bits per byte = 256-bit encryption

        /// <summary>The size of a 128-bit key in bytes.</summary>
        public const int ciKeySize128 = 128 >> 3;

        /// <summary>The size of a 192-bit key in bytes.</summary>
        public const int ciKeySize192 = 192 >> 3;

        /// <summary>The size of a 256-bit key in bytes.</summary>
        public const int ciKeySize256 = 256 >> 3;

        private const int ciKeyDerivationIterations = 100000;
        private const int ciPkcs1PaddingByteDifference = 11;

        public const string csOpenScSubkey = "SOFTWARE\\OpenSC Project\\PKCS11-Spy";
        public const string csOpenScSubpath = "\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll";

        private byte[] _abInitialisationVector;
        private string _sPkcs11Library;
        private AesCng _AesServices;
        private RNGCryptoServiceProvider _Randomness;
        private RSACng _RsaServices;
        private MD5Cng _MD5Services;
        private SHA1Cng _SHA1Services;
        private SHA256Cng _SHA256Services;
        private SHA384Cng _SHA384Services;
        private SHA512Cng _SHA512Services;
        private Pkcs11InteropFactories _Pkcs11Factories;
        private IPkcs11Library _Pkcs11Library;
        private ILibraryInfo _Pkcs11LibraryInfo;

        #region constructors

        public EncryptionServices()
        {
            _AesServices = new AesCng
            {
                BlockSize = ciAesBlockLength << 3,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            _MD5Services = new MD5Cng();
            _SHA1Services = new SHA1Cng();
            _SHA256Services = new SHA256Cng();
            _SHA384Services = new SHA384Cng();
            _SHA512Services = new SHA512Cng();
            _RsaServices = new RSACng();
            _Randomness = new RNGCryptoServiceProvider();
            _abInitialisationVector = new byte[ciAesBlockLength];

            _sPkcs11Library = string.Empty;
            _Pkcs11LibraryInfo = null;
            CheckForOpenSc();
        }

        #endregion

        #region properties

        /// <summary></summary>
        public string sPkcs11Library
        {
            get { return _sPkcs11Library; }
        }

        /// <summary></summary>
        public string Pkcs11LibraryCryptokiVersion
        {
            get { return (_Pkcs11LibraryInfo == null) ? string.Empty : _Pkcs11LibraryInfo.CryptokiVersion; }
        }

        /// <summary></summary>
        public string Pkcs11LibraryDescription
        {
            get { return (_Pkcs11LibraryInfo == null) ? string.Empty : _Pkcs11LibraryInfo.LibraryDescription; }
        }

        /// <summary></summary>
        public string Pkcs11LibraryManufacturer
        {
            get { return (_Pkcs11LibraryInfo == null) ? string.Empty : _Pkcs11LibraryInfo.ManufacturerId; }
        }

        /// <summary></summary>
        public string Pkcs11LibraryVersion
        {
            get { return (_Pkcs11LibraryInfo == null) ? string.Empty : _Pkcs11LibraryInfo.LibraryVersion; }
        }

        /// <summary></summary>
        public bool isWithOpenSc
        {
            get { return _Pkcs11Library != null; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        private void AddKeysToToken(ISlot Slot, PgpToken Token)
        {
            byte[] abExponent, abId, abModulus;
            bool isEncrypt, isVerify;
            ulong vKeyType;
            PgpKeyFlags.nFlags eKeyFlags;
            ISlotInfo SlotInfo;
            List<IObjectAttribute> ltAttributes, ltSearchTemplate;
            List<IObjectHandle> ltPublicKeys;

            if (Slot != null)
            {
                SlotInfo = Slot.GetSlotInfo();

                using (ISession Session = Slot.OpenSession(SessionType.ReadOnly))
                {
                    ltSearchTemplate = new List<IObjectAttribute> { Session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY) };
                    ltPublicKeys = Session.FindAllObjects(ltSearchTemplate);

                    foreach (IObjectHandle PublicKey in ltPublicKeys)
                    {
                        ltAttributes = Session.GetAttributeValue(PublicKey, new List<CKA> { CKA.CKA_ENCRYPT, CKA.CKA_ID, CKA.CKA_KEY_TYPE, CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_VERIFY });

                        isEncrypt = ltAttributes[0].GetValueAsBool();
                        abId = ltAttributes[1].GetValueAsByteArray();
                        vKeyType = ltAttributes[2].GetValueAsUlong();
                        abModulus = ltAttributes[3].GetValueAsByteArray();
                        abExponent = ltAttributes[4].GetValueAsByteArray();
                        isVerify = ltAttributes[5].GetValueAsBool();

                        if ((CKK)vKeyType == CKK.CKK_RSA)
                        {
                            if (!isEncrypt && isVerify)
                                eKeyFlags = PgpKeyFlags.nFlags.Certify | PgpKeyFlags.nFlags.Sign;
                            else if (isEncrypt && !isVerify)
                                eKeyFlags = PgpKeyFlags.nFlags.Encrypt;
                            else if (isEncrypt && isVerify)
                                eKeyFlags = PgpKeyFlags.nFlags.Authenticate;
                            else
                                eKeyFlags = PgpKeyFlags.nFlags.None;

                            Token.AddPublicKey(SlotInfo, abId, eKeyFlags, abModulus, abExponent);
                        }
                    }
                }
            }
        }

        /// <summary></summary>
        private void CheckForOpenSc()
        {
            string sProgramFiles;
            object ModuleValue;

            using (RegistryKey Pkcs11Key = Registry.LocalMachine.OpenSubKey(csOpenScSubkey, false))
            {
                if (Pkcs11Key != null)
                {
                    ModuleValue = Pkcs11Key.GetValue("Module");
                    if ((ModuleValue != null) && (File.Exists((string)ModuleValue)))
                        _sPkcs11Library = (string)ModuleValue;
                }
            }

            if (string.IsNullOrEmpty(_sPkcs11Library))
            {
                sProgramFiles = Environment.GetEnvironmentVariable("ProgramFiles");
                if (File.Exists(sProgramFiles + csOpenScSubpath))
                    _sPkcs11Library = sProgramFiles + csOpenScSubpath;
            }

            if (string.IsNullOrEmpty(_sPkcs11Library))
            {
                _Pkcs11Factories = null;
                _Pkcs11Library = null;
            }
            else
            {
                _Pkcs11Factories = new Pkcs11InteropFactories();
                _Pkcs11Library = _Pkcs11Factories.Pkcs11LibraryFactory.LoadPkcs11Library(_Pkcs11Factories, _sPkcs11Library, AppType.SingleThreaded);
                _Pkcs11LibraryInfo = _Pkcs11Library.GetInfo();
            }
        }

        public byte[] ComputeHash(byte[] abData, HashAlgorithmName HashAlgorithm)
        {
            byte[] abReturn = null;

            if (HashAlgorithm == HashAlgorithmName.MD5)
                abReturn = _MD5Services.ComputeHash(abData);
            else if (HashAlgorithm == HashAlgorithmName.SHA1)
                abReturn = _SHA1Services.ComputeHash(abData);
            else if (HashAlgorithm == HashAlgorithmName.SHA256)
                abReturn = _SHA256Services.ComputeHash(abData);
            else if (HashAlgorithm == HashAlgorithmName.SHA384)
                abReturn = _SHA384Services.ComputeHash(abData);
            else if (HashAlgorithm == HashAlgorithmName.SHA512)
                abReturn = _SHA512Services.ComputeHash(abData);

            return abReturn;
        }

        /// <summary></summary>
        public byte[] DecryptAes(byte[] abEncrypted, byte[] abKey)
        {
            byte[] abReturn = null;

            if ((abEncrypted != null) && (abEncrypted.Length > ciAesBlockLength) && (abKey != null))
            {
                _AesServices.Padding = PaddingMode.PKCS7;

                for (int i = 0; i < ciAesBlockLength; i++)
                    _abInitialisationVector[i] = abEncrypted[i];

                using (ICryptoTransform AesDecryptor = _AesServices.CreateDecryptor(abKey, _abInitialisationVector))
                {
                    using (MemoryStream EncryptedStream = new MemoryStream(abEncrypted, ciAesBlockLength, abEncrypted.Length - ciAesBlockLength))
                    {
                        try
                        {
                            using (CryptoStream AesCryptoStream = new CryptoStream(EncryptedStream, AesDecryptor, CryptoStreamMode.Read))
                            {

                                using (MemoryStream DecryptedStream = new MemoryStream())
                                {
                                    AesCryptoStream.CopyTo(DecryptedStream);
                                    abReturn = DecryptedStream.ToArray();
                                }
                            }
                        }
                        catch (CryptographicException)
                        {
                            //
                        }
                    }
                }
            }
            return abReturn;
        }

        /// <summary></summary>
        public void Dispose()
        {
            if (_AesServices != null)
            {
                _AesServices.Clear();
                _AesServices = null;
            }
            if (_MD5Services != null)
            {
                _MD5Services.Dispose();
                _MD5Services = null;
            }
            if (_SHA1Services != null)
            {
                _SHA1Services.Dispose();
                _SHA1Services = null;
            }
            if (_SHA256Services != null)
            {
                _SHA256Services.Dispose();
                _SHA256Services = null;
            }
            if (_SHA384Services != null)
            {
                _SHA384Services.Dispose();
                _SHA384Services = null;
            }
            if (_SHA512Services != null)
            {
                _SHA512Services.Dispose();
                _SHA512Services = null;
            }
            if (_Pkcs11Library != null)
            {
                _Pkcs11Library.Dispose();
                _Pkcs11Library = null;
            }
            if (_Randomness != null)
            {
                _Randomness.Dispose();
                _Randomness = null;
            }
            if (_RsaServices != null)
            {
                _RsaServices.Clear();
                _RsaServices = null;
            }
        }

        /// <summary></summary>
        public byte[] EncryptAes(byte[] abKey, byte[] abPlain)
        {
            byte[] abReturn = null;

            if ((abKey != null) && (abPlain != null))
            {
                _Randomness.GetBytes(_abInitialisationVector);
                _AesServices.Key = abKey;   // TODO SetKey
                _AesServices.IV = _abInitialisationVector;
                _AesServices.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform AesEncryptor = _AesServices.CreateEncryptor())
                {
                    using (MemoryStream AesMemoryStream = new MemoryStream())
                    {
                        AesMemoryStream.Write(_abInitialisationVector, 0, _abInitialisationVector.Length);
                        using (CryptoStream AesCryptoStream = new CryptoStream(AesMemoryStream, AesEncryptor, CryptoStreamMode.Write))
                        {
                            AesCryptoStream.Write(abPlain, 0, abPlain.Length);
                        }
                        abReturn = AesMemoryStream.ToArray();
                    }
                }
            }
            return abReturn;
        }

        /// <summary></summary>
        public byte[] EncryptAesBlock(byte[] abPlainBlock)
        {
            byte[] abReturn = null;

            if ((abPlainBlock != null) && (abPlainBlock.Length == ciAesBlockLength) && (_AesServices.Key != null) && (_AesServices.IV != null) && (_AesServices.Padding == PaddingMode.Zeros))
            {
                using (ICryptoTransform AesEncryptor = _AesServices.CreateEncryptor())
                {
                    using (MemoryStream AesMemoryStream = new MemoryStream())
                    {
                        using (CryptoStream AesCryptoStream = new CryptoStream(AesMemoryStream, AesEncryptor, CryptoStreamMode.Write))
                            AesCryptoStream.Write(abPlainBlock, 0, ciAesBlockLength);

                        abReturn = AesMemoryStream.ToArray();
                    }
                }

            }

            if ((abReturn == null) || (abReturn.Length != ciAesBlockLength))
                throw new CryptographicException("EncryptionServices.EncryptAesBlock()");
            else
                return abReturn;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public void GetRandomBytes(byte[] abBuffer)
        {
            if (abBuffer == null)
                throw new ArgumentNullException("abBuffer in EncryptionServices.GetRandomBytes().");
            else
                _Randomness.GetBytes(abBuffer);
        }

        /// <summary></summary>
        public void InitialiseEncryptAesBlocks(byte[] abKey)
        {
            if ((abKey == null) || ((abKey.Length != ciKeySize128) && (abKey.Length != ciKeySize192) && (abKey.Length != ciKeySize256)))
            {
                throw new ArgumentException("Invalid abKey in EncryptionServices.InitialiseEncryptAesBlock().");
            }
            else
            {
                _AesServices.Key = abKey;   // TODO SetKey with ArgumentException

                if (_AesServices.IV != null)
                    GetRandomBytes(_AesServices.IV);

                _AesServices.IV = new byte[ciAesBlockLength];
                for (int i = 0; i < ciAesBlockLength; i++)
                    _AesServices.IV[i] = 0;

                _AesServices.Padding = PaddingMode.Zeros;
            }
        }

        /// <summary></summary>
        public byte[] PasswordToAesKey(byte[] abPassword, byte[] abSalt)
        {
            byte[] abReturn = null;

            if ((abPassword == null) || (abSalt == null))
            {
                throw new ArgumentException("Argument in EncryptionServices.PasswordToAesKey must not be null.");
            }
            else
            {
                // derive a key from the password with a database-specific salt and a high number of iterations to hinder dictionary attacks
                using (Rfc2898DeriveBytes KeyDerivationFunction = new Rfc2898DeriveBytes(abPassword, abSalt, ciKeyDerivationIterations))
                    abReturn = KeyDerivationFunction.GetBytes(ciAes256KeyBytesLength);
            }
            return abReturn;
        }

        public void ReadTokens(List<PgpToken> ltTokens)
        {
            ITokenInfo TokenInfo;
            List<ISlot> ltSlots;
            PgpToken Token;

            if (isWithOpenSc)
            {
                ltTokens.RemoveAll(t => t.isOnSmartCard);

                ltSlots = _Pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                if (ltSlots != null)
                {
                    foreach (ISlot Slot in ltSlots)
                    {
                        TokenInfo = Slot.GetTokenInfo();

                        Token = ltTokens.Find(t => t.sSerialNumber == TokenInfo.SerialNumber);
                        if (Token == null)
                        {
                            Token = new PgpToken(TokenInfo, this);
                            ltTokens.Add(Token);
                        }
                        AddKeysToToken(Slot, Token);
                    }
                }
            }
        }

        /// <summary></summary>
        public bool VerifyHash(byte[] abData, byte[] abHash, HashAlgorithmName HashAlgorithm)
        {
            bool isReturn = false;
            byte[] abNewHash;

            if ((abData != null) && (abHash != null))
            {
                abNewHash = ComputeHash(abData, HashAlgorithm);

                if ((abNewHash != null) && (abNewHash.Length == abHash.Length))
                {
                    isReturn = true;

                    for (int i = 0; i < abHash.Length; i++)
                        isReturn = isReturn && (abNewHash[i] == abHash[i]);
                }
            }
            return isReturn;
        }

        /// <summary></summary>
        public bool VerifyRsa(byte[] abData, byte[] abSignature, HashAlgorithmName HashAlgorithm, PgpPublicKey SignatureKey)
        {
            bool isReturn = false;

            if ((abData != null) && (abSignature != null) && (SignatureKey != null))
            {
                _RsaServices.ImportParameters(SignatureKey.KeyParameters);
                isReturn = _RsaServices.VerifyData(abData, abSignature, HashAlgorithm, RSASignaturePadding.Pkcs1);
            }
            return isReturn;
        }
        #endregion
    }
}
