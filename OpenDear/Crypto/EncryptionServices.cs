namespace OpenDear.Crypto
{
    using System;
    using System.IO;
    using Microsoft.Win32;
    using Net.Pkcs11Interop.Common;
    using System.Security.Cryptography;
    using Net.Pkcs11Interop.HighLevelAPI;


    /// <summary>All cryptography other than PGP, no keys stored here.</summary>
    public class EncryptionServices
    {
        public const int ciIvOrSaltBytesLength = 16;     // 16 * 8 bits per byte = 128-bit, the only block size allowed for AES
                                                         // the salt size could be different, but this produces the same number of bytes with a key or a password for encryption

        public const int ciAesKeyBytesLength = 32;       // 32 * 8 bits per byte = 256-bit encryption

        private const int ciKeyDerivationIterations = 100000;
        private const int ciPkcs1PaddingByteDifference = 11;

        public const string csOpenScSubkey = "SOFTWARE\\OpenSC Project\\PKCS11-Spy";
        public const string csOpenScSubpath = "\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll";

        private byte[] _abInitialisationVector;
        private string _sPkcs11Library;
        private AesCng _AesServices;
        private RNGCryptoServiceProvider _Randomness;
        private RSACng _RsaServices;
        private SHA256Cng _HashServices;
        private Pkcs11InteropFactories _Pkcs11Factories;
        private IPkcs11Library _Pkcs11Library;
        private ILibraryInfo _Pkcs11LibraryInfo;

        #region constructors

        public EncryptionServices()
        {
            _AesServices = new AesCng
            {
                BlockSize = ciIvOrSaltBytesLength << 3,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            _HashServices = new SHA256Cng();
            _RsaServices = new RSACng();
            _Randomness = new RNGCryptoServiceProvider();
            _abInitialisationVector = new byte[ciIvOrSaltBytesLength];

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

        /// <summary></summary>
        public byte[] DecryptAes(byte[] abEncrypted, byte[] abKey)
        {
            byte[] abReturn = null;

            if ((abEncrypted != null) && (abEncrypted.Length > ciIvOrSaltBytesLength) && (abKey != null))
            {
                for (int i = 0; i < ciIvOrSaltBytesLength; i++)
                    _abInitialisationVector[i] = abEncrypted[i];

                using (ICryptoTransform AesDecryptor = _AesServices.CreateDecryptor(abKey, _abInitialisationVector))
                {
                    using (MemoryStream EncryptedStream = new MemoryStream(abEncrypted, ciIvOrSaltBytesLength, abEncrypted.Length - ciIvOrSaltBytesLength))
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
            if (_HashServices != null)
            {
                _HashServices.Dispose();
                _HashServices = null;
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
        public byte[] EncryptAes(byte[] abPlain, byte[] abKey)
        {
            byte[] abReturn = null;

            if ((abPlain != null) && (abKey != null))
            {
                _Randomness.GetBytes(_abInitialisationVector);
                _AesServices.Key = abKey;
                _AesServices.IV = _abInitialisationVector;

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
        /// <param name=""></param>
        public void GetRandomBytes(byte[] abBuffer)
        {
            _Randomness.GetBytes(abBuffer);
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public void GetRandomBytes(byte[] abBuffer, int iCount)
        {
            if ((iCount < 0) || (iCount > abBuffer.Length))
                throw new ArgumentException("iCount=" + iCount.ToString() + " is out of range in GetRandomBytes()");
            else if (iCount > 0)
                _Randomness.GetBytes(abBuffer, 0, iCount);
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
                    abReturn = KeyDerivationFunction.GetBytes(ciAesKeyBytesLength);
            }
            return abReturn;
        }

        #endregion
    }
}
