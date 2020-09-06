namespace OpenDear.Crypto
{
    using System;
    using System.IO;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using Net.Pkcs11Interop.HighLevelAPI;


    /// <summary>Implements RFC 4880 section 5.2. Signature Packet.</summary>
    public class PgpSignature : PgpPacket, IEquatable<PgpSignature>
    {
        [Flags]
        public enum nTranslatedKeyFlags
        {
            None = 0x00,
            Certify = 0x01,
            VerifyCertificates = 0x02,
            Sign = 0x04,
            VerifySignatures = 0x08,
            Decrypt = 0x10,
            Encrypt = 0x20,
            Authenticate = 0x40,
            VerifyAuthenticity = 0x80,
        }

        public enum nVerified { False, KeyNotFound, Pending, True };


        /// <summary>Only version 4 Signature Packets are implemented, see RFC 4880 section 5.2.3. Version 4 Signature Packet Format.</summary>
        private const byte cbAllowedVersion = 4;

        private const byte cbKeyCertificationTag = 0x99;

        private const byte cbUserIdCertificationTag = 0xb4;

        private const byte cbUserAttributeCertificationTag = 0xd1;

        /// <summary>Version number + signature type + public-key algorithm + hash algorithm + hashed subpackets length (2 bytes) = 6 bytes, see RFC 4880 section 5.2.3. Version 4 Signature Packet Format.</summary>
        private const int ciSignatureHeaderLength = 6;

        private byte[] _abFingerprint, _abHashFingerprint, _abSignature;
        private int _iHashedLength, _iSignatureBits;
        private nVerified _eVerified;
        private nSignatureType _eSignatureType;
        private nTranslatedKeyFlags _eTranslatedKeyFlags;
        private nPublicKeyAlgorithm _ePublicKeyAlgorithm;
        private nHashAlgorithm _eHashAlgorithm;
        private PgpPrivateKey _PrivateKeyPacket;
        private PgpPublicKey _PublicKeyPacket;
        private PgpUserId _UserIdPacket;
        private EncryptionServices _Cryptography;
        private List<PgpSignatureSubpacket> _ltSubpackets;


        #region constructors

        public PgpSignature(PgpPacket FromPacket, PgpPublicKey PublicMasterKeyPacket, PgpUserId UserIdPacket, List<PgpToken> ltTokens, EncryptionServices Cryptography) : base(FromPacket)
        {
            Initialise(nSignatureType.PositiveCertification);
            _PublicKeyPacket = PublicMasterKeyPacket;
            _UserIdPacket = UserIdPacket;
            _Cryptography = Cryptography;
            Parse(_PublicKeyPacket, ltTokens);
        }

        public PgpSignature(PgpPacket FromPacket, PgpPublicKey PublicMasterKeyPacket, PgpPublicKey PublicKeyPacket, EncryptionServices Cryptography) : base(FromPacket)
        {
            Initialise(nSignatureType.SubkeyBinding);
            _PublicKeyPacket = PublicKeyPacket;
            _Cryptography = Cryptography;
            Parse(PublicMasterKeyPacket);
        }

        public PgpSignature(PgpPacket FromPacket, PgpPrivateKey PrivateMasterKeyPacket, PgpUserId UserIdPacket, List<PgpToken> ltTokens, EncryptionServices Cryptography) : base(FromPacket)
        {
            Initialise(nSignatureType.PositiveCertification);
            _PrivateKeyPacket = PrivateMasterKeyPacket;
            _PublicKeyPacket = PrivateMasterKeyPacket.PublicKey;
            _UserIdPacket = UserIdPacket;
            _Cryptography = Cryptography;
            Parse(_PublicKeyPacket, ltTokens);
        }

        public PgpSignature(PgpPacket FromPacket, PgpPublicKey PublicMasterKeyPacket, PgpPrivateKey PrivateKeyPacket, EncryptionServices Cryptography) : base(FromPacket)
        {
            Initialise(nSignatureType.SubkeyBinding);
            _PrivateKeyPacket = PrivateKeyPacket;
            _PublicKeyPacket = PrivateKeyPacket.PublicKey;
            _Cryptography = Cryptography;
            Parse(PublicMasterKeyPacket);
        }

        public PgpSignature(ISlotInfo SlotInfo, byte[] abId, PgpKeyFlags.nFlags eKeyFlags, byte[] abModulus, byte[] abExponent, EncryptionServices Cryptography) : base(nPacketTag.Signature)
        {
            PgpSignatureSubpacket NewSubpacket;

            Initialise((eKeyFlags & PgpKeyFlags.nFlags.Sign) == 0 ? nSignatureType.SubkeyBinding : nSignatureType.PositiveCertification);

            if ((SlotInfo == null) || (abId == null) || (abModulus == null) || (abExponent == null) || (Cryptography == null))
            {
                _eStatus = nStatus.MissingArgument;
            }
            else
            {
                _eStatus = nStatus.OK;
                _Cryptography = Cryptography;
                _PublicKeyPacket = new PgpPublicKey(SlotInfo, abId, (eKeyFlags & PgpKeyFlags.nFlags.Sign) == 0 ? nPacketTag.PublicSubkey : nPacketTag.PublicKey, DateTime.Now, nPublicKeyAlgorithm.RsaEncryptOrSign, abModulus, abExponent);
                
                NewSubpacket = new PgpKeyFlags(eKeyFlags);
                _ltSubpackets.Add(NewSubpacket);
                _eTranslatedKeyFlags = TranslateKeyFlags();
            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public DateTime? CreatedKey
        {
            get
            {
                if (_PublicKeyPacket == null)
                    return null;
                else
                    return _PublicKeyPacket.Created;
            }
        }

        /// <summary></summary>
        public DateTime? CreatedSignature
        {
            get
            {
                PgpCreationTime CreationTimeSubpacket = (PgpCreationTime)GetSubpaket(PgpSignatureSubpacket.nSubpacketType.CreationTime);

                if (CreationTimeSubpacket == null)
                    return null;
                else
                    return CreationTimeSubpacket.Created;
            }
        }

        /// <summary></summary>
        public DateTime? Expires
        {
            get
            {
                uint uSeconds;
                DateTime? SignatureCreationDate = CreatedSignature;
                PgpKeyExpireTime KeyExpireTimeSubpacket = (PgpKeyExpireTime)GetSubpaket(PgpSignatureSubpacket.nSubpacketType.KeyExpireTime);

                if ((SignatureCreationDate == null) || (KeyExpireTimeSubpacket == null))
                    return null;
                else
                {
                    uSeconds = (uint)(SignatureCreationDate.Value.ToUniversalTime().Ticks / TimeSpan.TicksPerSecond - ckSeconds_1_1_1970_Utc);
                    return new DateTime((ckSeconds_1_1_1970_Utc + uSeconds + KeyExpireTimeSubpacket.uSecondsValid) * TimeSpan.TicksPerSecond);
                }
            }
        }

        /// <summary></summary>
        public byte[] abExponent
        {
            get
            {
                if (_PublicKeyPacket == null)
                    return null;
                else
                    return _PublicKeyPacket.KeyParameters.Exponent;
            }
        }

        /// <summary>SHA-1 hash of the public key packet, see RFC 4880 section 12.2. Key IDs and Fingerprints</summary>
        public byte[] abFingerprint
        {
            get { return _abFingerprint; }
        }

        /// <summary></summary>
        public nHashAlgorithm eHashAlgorithm
        {
            get { return _eHashAlgorithm; }
        }

        public PgpKeyFlags.nFlags eKeyFlags
        {
            get
            {
                PgpKeyFlags KeyFlagsSubpacket = (PgpKeyFlags)GetSubpaket(PgpSignatureSubpacket.nSubpacketType.KeyFlags);

                return KeyFlagsSubpacket == null ? PgpKeyFlags.nFlags.None : KeyFlagsSubpacket.eFlags;
            }
        }

        /// <summary>Locks this subkey and overwrites its secret data.</summary>
        public void Lock()
        {
            if (_PrivateKeyPacket != null)
                _PrivateKeyPacket.Lock();
        }

        /// <summary></summary>
        public byte[] abMasterKeyFingerprint
        {
            get
            {
                PgpMasterKeyFingerprint FingerprintSubpacket = (PgpMasterKeyFingerprint)GetSubpaket(PgpSignatureSubpacket.nSubpacketType.MasterKeyFingerprint);

                if (FingerprintSubpacket == null)
                    return null;
                else
                    return FingerprintSubpacket.abFingerprint;
            }
        }

        /// <summary></summary>
        public byte[] abModulus
        {
            get
            {
                if (_PublicKeyPacket == null)
                    return null;
                else
                    return _PublicKeyPacket.KeyParameters.Modulus;
            }
        }

        public int iModulusBits
        {
            get { return _PublicKeyPacket == null ? 0 : _PublicKeyPacket.iModulusBits; }
        }

        public string sModulusBits
        {
            get { return _PublicKeyPacket == null ? string.Empty : _PublicKeyPacket.iModulusBits.ToString(); }
        }

        /// <summary></summary>
        public nPublicKeyAlgorithm ePublicKeyAlgorithm
        {
            get { return _ePublicKeyAlgorithm; }
        }

        /// <summary></summary>
        public PgpPrivateKey PrivateKeyPacket
        {
            get { return _PrivateKeyPacket; }
        }

        /// <summary></summary>
        public PgpPublicKey PublicKeyPacket
        {
            get { return _PublicKeyPacket; }
        }

        /// <summary></summary>
        public byte[] abSignature
        {
            get { return _abSignature; }
        }

        /// <summary></summary>
        public nSignatureType eSignatureType
        {
            get { return _eSignatureType; }
        }

        public nTranslatedKeyFlags eTranslatedKeyFlags
        {
            get { return _eTranslatedKeyFlags; }
        }

        /// <summary></summary>
        public nVerified eVerified
        {
            get { return _eVerified; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        private byte[] ComputeFingerprint()
        {
            byte[] abBytesToHash, abReturn = null;

            if (_PublicKeyPacket != null)
            {
                using (MemoryStream StreamToHash = new MemoryStream())
                {
                    HashPublicKeyData(StreamToHash, _PublicKeyPacket);
                    abBytesToHash = StreamToHash.ToArray();
                }
                abReturn = _Cryptography.ComputeHash(abBytesToHash, HashAlgorithmName.SHA1);
            }

            return abReturn;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public bool Equals(PgpSignature Other)
        {
            bool isReturn;

            if ((_abSignature != null) && (Other != null) && (Other.abSignature != null) && (_abSignature.Length == Other.abSignature.Length))
            {
                isReturn = true;

                for (int i = 0; i < _abSignature.Length; i++)
                    isReturn = isReturn && (_abSignature[i] == Other.abSignature[i]);
            }
            else
                isReturn = false;

            return isReturn;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public override bool Equals(object Other)
        {
            if (Other == null)
            {
                return false;
            }
            else
            {
                if (Other is PgpSignature OtherSignature)
                    return Equals(OtherSignature);
                else
                    return false;
            }
        }

        /// <summary></summary>
        public override int GetHashCode()
        {
            return 0;
        }

        private PgpSignatureSubpacket GetSubpaket(PgpSignatureSubpacket.nSubpacketType eSubpacketType)
        {
            PgpSignatureSubpacket Return = null;

            if (_ltSubpackets != null)
                Return = _ltSubpackets.Find(p => p.eType == eSubpacketType);

            return Return;
        }

        /// <summary></summary>
        private void Initialise(nSignatureType eSignatureType)
        {
            _abFingerprint = _abHashFingerprint = _abSignature = null;
            _iHashedLength = _iSignatureBits = 0;
            _eVerified = nVerified.Pending;
            _eSignatureType = eSignatureType;
            _eTranslatedKeyFlags = nTranslatedKeyFlags.None;
            _ePublicKeyAlgorithm = nPublicKeyAlgorithm.RsaEncryptOrSign;
            _eHashAlgorithm = nHashAlgorithm.Sha512;
            _PrivateKeyPacket = null;
            _PublicKeyPacket = null;
            _UserIdPacket = null;
            _Cryptography = null;
            _ltSubpackets = new List<PgpSignatureSubpacket>();
        }

        /// <summary></summary>
        public void Parse(PgpPublicKey MasterKey, List<PgpToken> ltTokens = null)
        {
            bool isThisMasterKey = true;
            byte bVersion;
            byte[] abMasterFingerprint;
            int i, iSubpacketPointer, iSignatureBytes, iUnhashedLength;
            PgpSignature FoundSubkey;
            PgpSignatureSubpacket DecodedPgpSubpacket, RawPgpSubpacket;

            if ((_abRawBytes == null) || (_abRawBytes.Length < _iHeaderLength + ciSignatureHeaderLength) || (_ePacketTag != nPacketTag.Signature))
            {
                _eStatus = nStatus.ParseError;
            }
            else if (_eStatus == nStatus.OK)
            {
                bVersion = _abRawBytes[_iHeaderLength];

                if (bVersion == cbAllowedVersion)
                {
                    _eSignatureType = (nSignatureType)_abRawBytes[_iHeaderLength + 1];
                    _ePublicKeyAlgorithm = (nPublicKeyAlgorithm)_abRawBytes[_iHeaderLength + 2];
                    _eHashAlgorithm = (nHashAlgorithm)_abRawBytes[_iHeaderLength + 3];
                    _iHashedLength = (_abRawBytes[_iHeaderLength + 4] << 8) | _abRawBytes[_iHeaderLength + 5];

                    if (((_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaEncryptOrSign) || (_ePublicKeyAlgorithm == nPublicKeyAlgorithm.RsaSignOnly)) &&
                       (_eHashAlgorithm == nHashAlgorithm.Sha1) || (_eHashAlgorithm == nHashAlgorithm.Sha256) || (_eHashAlgorithm == nHashAlgorithm.Sha384) || (_eHashAlgorithm == nHashAlgorithm.Sha512))
                    {
                        iSubpacketPointer = _iHeaderLength + ciSignatureHeaderLength;
                        while ((_eStatus == nStatus.OK) && (iSubpacketPointer < _iHeaderLength + ciSignatureHeaderLength + _iHashedLength))
                        {
                            RawPgpSubpacket = new PgpSignatureSubpacket(_abRawBytes, iSubpacketPointer);
                            if (RawPgpSubpacket.eStatus == nStatus.OK)
                            {
                                switch (RawPgpSubpacket.eType)
                                {
                                    case PgpSignatureSubpacket.nSubpacketType.CreationTime: DecodedPgpSubpacket = new PgpCreationTime(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.KeyExpireTime: DecodedPgpSubpacket = new PgpKeyExpireTime(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.PreferredSymmetricAlgorithms: DecodedPgpSubpacket = new PgpPreferredSymmetricAlgorithms(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.IssuerKeyId: DecodedPgpSubpacket = new PgpIssuerKeyId(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.PreferredHashAlgorithms: DecodedPgpSubpacket = new PgpPreferredHashAlgorithms(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.PreferredCompressionAlgorithms: DecodedPgpSubpacket = new PgpPreferredCompressionAlgorithms(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.KeyServerPreferences: DecodedPgpSubpacket = new PgpKeyServerPreferences(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.PrimaryUserId: DecodedPgpSubpacket = new PgpPrimaryUserId(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.KeyFlags: DecodedPgpSubpacket = new PgpKeyFlags(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.RevocationReason: DecodedPgpSubpacket = new PgpRevocationReason(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.Features: DecodedPgpSubpacket = new PgpFeatures(RawPgpSubpacket); break;
                                    case PgpSignatureSubpacket.nSubpacketType.MasterKeyFingerprint: DecodedPgpSubpacket = new PgpMasterKeyFingerprint(RawPgpSubpacket); break;
                                    default: DecodedPgpSubpacket = null; Console.WriteLine("not implemented: eType=" + RawPgpSubpacket.eType.ToString()); break;
                                }

                                if ((DecodedPgpSubpacket == null) || (DecodedPgpSubpacket.eStatus != nStatus.OK))
                                {
                                    _eStatus = nStatus.ParseError;
                                }
                                else
                                {
                                    // Console.WriteLine("found eType=" + RawPgpSubpacket.eType.ToString());
                                    _ltSubpackets.Add(DecodedPgpSubpacket);
                                    iSubpacketPointer += (RawPgpSubpacket.iHeaderLength + RawPgpSubpacket.iDataLength);
                                }
                            }
                            else
                                _eStatus = nStatus.ParseError;
                        }

                        iUnhashedLength = (_abRawBytes[iSubpacketPointer] << 8) | _abRawBytes[iSubpacketPointer + 1];
                        iSubpacketPointer += 2;

                        while ((_eStatus == nStatus.OK) && (iSubpacketPointer < _iHashedLength + iUnhashedLength + 8))
                        {
                            RawPgpSubpacket = new PgpSignatureSubpacket(_abRawBytes, iSubpacketPointer);
                            if (RawPgpSubpacket.eStatus == nStatus.OK)
                            {
                                switch (RawPgpSubpacket.eType)
                                {
                                    case PgpSignatureSubpacket.nSubpacketType.IssuerKeyId: DecodedPgpSubpacket = new PgpIssuerKeyId(RawPgpSubpacket); break;
                                    default: DecodedPgpSubpacket = null; Console.WriteLine("not implemented: eType=" + RawPgpSubpacket.eType.ToString()); break;
                                }

                                if ((DecodedPgpSubpacket == null) || (DecodedPgpSubpacket.eStatus != nStatus.OK))
                                {
                                    _eStatus = nStatus.ParseError;
                                }
                                else
                                {
                                    _ltSubpackets.Add(DecodedPgpSubpacket);
                                    iSubpacketPointer += (RawPgpSubpacket.iHeaderLength + RawPgpSubpacket.iDataLength);
                                }
                            }
                            else
                                _eStatus = nStatus.ParseError;
                        }

                        _abFingerprint = ComputeFingerprint();
                        _eTranslatedKeyFlags = TranslateKeyFlags();

                        if (_abRawBytes.Length > iSubpacketPointer + 2)
                        {
                            _abHashFingerprint = CopyFromRawBytes(iSubpacketPointer, 2);
                            _iSignatureBits = _abRawBytes[iSubpacketPointer + 2] << 8 | _abRawBytes[iSubpacketPointer + 3];
                            iSignatureBytes = (_iSignatureBits + 7) >> 3;
                            iSubpacketPointer += 4;

                            if (_abRawBytes.Length == iSubpacketPointer + iSignatureBytes)
                            {
                                _abSignature = CopyFromRawBytes(iSubpacketPointer, iSignatureBytes);

                                if (_PublicKeyPacket != null)
                                    _PublicKeyPacket.Signature = this;

                                abMasterFingerprint = abMasterKeyFingerprint;   // do the underlying checks only once

                                if ((abMasterFingerprint != null) && (abMasterFingerprint.Length == ciSha1FingerprintLength) && (MasterKey.Signature != null)
                                    && (MasterKey.Signature.abFingerprint != null) && (MasterKey.Signature.abFingerprint.Length == ciSha1FingerprintLength))
                                {
                                    for (i = 0; i < ciSha1FingerprintLength; i++)
                                        isThisMasterKey = isThisMasterKey && (abMasterFingerprint[i] == MasterKey.Signature.abFingerprint[i]);

                                    if (!isThisMasterKey)
                                    {
                                        MasterKey = null;

                                        if (ltTokens != null)
                                        {
                                            foreach (PgpToken Token in ltTokens)
                                            {
                                                if (MasterKey == null)
                                                {
                                                    FoundSubkey = Token.GetSubkey(abMasterFingerprint);

                                                    if (FoundSubkey != null)
                                                        MasterKey = FoundSubkey.PublicKeyPacket;
                                                }
                                            }
                                        }
                                    }
                                }

                                if (MasterKey == null)
                                    _eVerified = nVerified.KeyNotFound;
                                else if (Verify(MasterKey))
                                    _eVerified = nVerified.True;
                                else
                                    _eVerified = nVerified.False;
                            }
                            else
                                _eStatus = nStatus.ParseError;
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

        /// <summary></summary>
        private void HashPublicKeyData(MemoryStream StreamToHash, PgpPublicKey PublicKey)
        {
            StreamToHash.WriteByte(cbKeyCertificationTag);
            StreamToHash.WriteByte((byte)((PublicKey.iDataLength >> 8) & 0xff));
            StreamToHash.WriteByte((byte)(PublicKey.iDataLength & 0xff));
            StreamToHash.Write(PublicKey.abRawBytes, PublicKey.iHeaderLength, PublicKey.iDataLength);
        }

        /// <summary></summary>
        private void HashTrailerData(MemoryStream StreamToHash)
        {
            int iLength = _iHashedLength + ciSignatureHeaderLength;

            StreamToHash.Write(_abRawBytes, _iHeaderLength, iLength);
            StreamToHash.WriteByte(cbAllowedVersion);
            StreamToHash.WriteByte(0xff);
            StreamToHash.WriteByte((byte)((iLength >> 24) & 0xff));
            StreamToHash.WriteByte((byte)((iLength >> 16) & 0xff));
            StreamToHash.WriteByte((byte)((iLength >> 8) & 0xff));
            StreamToHash.WriteByte((byte)(iLength & 0xff));
        }

        /// <summary></summary>
        private void HashUserIdData(MemoryStream StreamToHash, PgpUserId UserId)
        {
            StreamToHash.WriteByte(cbUserIdCertificationTag);
            StreamToHash.WriteByte((byte)((UserId.iDataLength >> 24) & 0xff));
            StreamToHash.WriteByte((byte)((UserId.iDataLength >> 16) & 0xff));
            StreamToHash.WriteByte((byte)((UserId.iDataLength >> 8) & 0xff));
            StreamToHash.WriteByte((byte)(UserId.iDataLength & 0xff));
            StreamToHash.Write(UserId.abRawBytes, UserId.iHeaderLength, UserId.iDataLength);
        }

        /// <summary></summary>
        private nTranslatedKeyFlags TranslateKeyFlags()
        {
            PgpKeyFlags.nFlags eTranslateFrom = eKeyFlags;
            nTranslatedKeyFlags eReturn = nTranslatedKeyFlags.None;

            if (_PrivateKeyPacket != null)
            {
                if ((eTranslateFrom & PgpKeyFlags.nFlags.Certify) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.Certify;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Sign) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.Sign;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Encrypt) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.Decrypt;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Authenticate) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.Authenticate;
            }

            if (_PublicKeyPacket != null)
            {
                if ((eTranslateFrom & PgpKeyFlags.nFlags.Certify) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.VerifyCertificates;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Sign) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.VerifySignatures;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Encrypt) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.Encrypt;

                if ((eTranslateFrom & PgpKeyFlags.nFlags.Authenticate) != PgpKeyFlags.nFlags.None)
                    eReturn |= nTranslatedKeyFlags.VerifyAuthenticity;
            }

            return eReturn;
        }

        /// <summary>Unlocks this subkey with the passphrase and decrypts its secret data.</summary>
        public bool Unlock(byte[] abPassphrase)
        {
            bool isReturn = false;

            if (_PrivateKeyPacket != null)
                isReturn = _PrivateKeyPacket.Unlock(abPassphrase);

            return isReturn;
        }

        /// <summary></summary>
        private bool Verify(PgpPublicKey MasterKey)
        {
            byte[] abHashedData, abBytesToHash;
            bool isReturn = false;
            HashAlgorithmName HashAlgorithm;

            abHashedData = abBytesToHash = null;

            using (MemoryStream StreamToHash = new MemoryStream())
            {
                if ((_eSignatureType == nSignatureType.GenericCertification) || (_eSignatureType == nSignatureType.PersonaCertification) || (_eSignatureType == nSignatureType.CasualCertification) || (_eSignatureType == nSignatureType.PositiveCertification))
                {
                    HashPublicKeyData(StreamToHash, MasterKey);
                    HashUserIdData(StreamToHash, _UserIdPacket);
                    HashTrailerData(StreamToHash);
                }
                else if (_eSignatureType == nSignatureType.SubkeyBinding)
                {
                    HashPublicKeyData(StreamToHash, MasterKey);
                    HashPublicKeyData(StreamToHash, _PublicKeyPacket);
                    HashTrailerData(StreamToHash);
                }
                abBytesToHash = StreamToHash.ToArray();
            }

            switch (_eHashAlgorithm)
            {
                case nHashAlgorithm.Sha1: HashAlgorithm = HashAlgorithmName.SHA1; break;
                case nHashAlgorithm.Sha256: HashAlgorithm = HashAlgorithmName.SHA256; break;
                case nHashAlgorithm.Sha384: HashAlgorithm = HashAlgorithmName.SHA384; break;
                case nHashAlgorithm.Sha512: HashAlgorithm = HashAlgorithmName.SHA512; break;
                default: HashAlgorithm = HashAlgorithmName.MD5; break;   // use MD5 as null value
            }

            if (HashAlgorithm != HashAlgorithmName.MD5)
                abHashedData = _Cryptography.ComputeHash(abBytesToHash, HashAlgorithm);

            if ((abHashedData != null) && (abHashedData[0] == _abHashFingerprint[0]) && (abHashedData[1] == _abHashFingerprint[1]) && (HashAlgorithm != HashAlgorithmName.MD5))
                isReturn = _Cryptography.VerifyRsa(abBytesToHash, _abSignature, HashAlgorithm, MasterKey);

            return isReturn;
        }
        #endregion
    }
}
