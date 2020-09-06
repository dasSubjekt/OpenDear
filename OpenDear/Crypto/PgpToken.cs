namespace OpenDear.Crypto
{
    using System;
    using System.Linq;
    using System.Collections.Generic;
    using Net.Pkcs11Interop.HighLevelAPI;
 

    public class PgpToken : IEquatable<PgpToken>
    {
        public enum nStatus { OK, ParseErrorRaw, ParseErrorSub, Undefined };
        public enum nType { Private, Public, Symmetric, Undefined };

        private readonly nStatus _eStatus;
        private nType _eType;
        private string _sSlotName;
        private readonly ITokenInfo _TokenInfo;
        private PgpUserId _UserIdPacket;
        private readonly EncryptionServices _Cryptography;
        private PgpPacket _KeyPacket;
        private List<PgpSignature> _ltSubkeys;


        #region constructors

        /// <summary>Base constructor for initialisation.</summary>
        private PgpToken(EncryptionServices Cryptography)
        {
            _eStatus = nStatus.Undefined;
            _eType = nType.Undefined;
            _sSlotName = string.Empty;
            _TokenInfo = null;
            _UserIdPacket = null;
            _Cryptography = Cryptography;
            _KeyPacket = null;
            _ltSubkeys = new List<PgpSignature>();
        }

        /// <summary>Constructor for OpenPGP smard card hardware tokens.</summary>
        public PgpToken(ITokenInfo TokenInfo, EncryptionServices Cryptography) : this(Cryptography)
        {
            _TokenInfo = TokenInfo;
        }

        /// <summary>Constructor for OpenPGP keyring files.</summary>
        public PgpToken(byte[] abKeyBytes, List<PgpToken> ltTokens, EncryptionServices Cryptography) : this(Cryptography)
        {
            bool isPublicKey = true;
            int iPgpPacketPointer = 0;
            PgpPacket DecodedPgpPacket, RawPgpPacket;

            if (abKeyBytes != null)
            {
                _eStatus = nStatus.OK;

                while ((_eStatus == nStatus.OK) && (iPgpPacketPointer < abKeyBytes.Length - 2))
                {
                    RawPgpPacket = new PgpPacket(abKeyBytes, iPgpPacketPointer);
                    if (RawPgpPacket.eStatus == PgpPacketBase.nStatus.OK)
                    {
                        switch (RawPgpPacket.ePacketTag)
                        {
                            case PgpPacket.nPacketTag.PrivateKey:
                            case PgpPacket.nPacketTag.PrivateSubkey: DecodedPgpPacket = ParsePrivateKeyPacket(RawPgpPacket); break;
                            case PgpPacket.nPacketTag.PublicKey:
                            case PgpPacket.nPacketTag.PublicSubkey: DecodedPgpPacket = ParsePublicKeyPacket(RawPgpPacket); break;
                            case PgpPacket.nPacketTag.Signature: DecodedPgpPacket = ParseSignaturePacket(RawPgpPacket, ltTokens); break;
                            case PgpPacket.nPacketTag.UserId: DecodedPgpPacket = ParseUserIdPacket(RawPgpPacket); break;
                            default: DecodedPgpPacket = null; Console.WriteLine("not implemented: ePacketTag=" + RawPgpPacket.ePacketTag.ToString()); break;
                        }
                        if ((DecodedPgpPacket == null) || (DecodedPgpPacket.eStatus != PgpPacketBase.nStatus.OK))
                            _eStatus = nStatus.ParseErrorSub;
                        // else
                        //     Console.WriteLine("   Found ePacketTag=" + RawPgpPacket.ePacketTag.ToString() + " iHeaderLength=" + RawPgpPacket.iHeaderLength.ToString() + ", iDataLength=" + RawPgpPacket.iDataLength.ToString());
                        
                        iPgpPacketPointer += (RawPgpPacket.iHeaderLength + RawPgpPacket.iPartialHeaders + RawPgpPacket.iDataLength);
                    }
                    else
                        _eStatus = nStatus.ParseErrorRaw;
                }

                if (((_eStatus == nStatus.OK) && (iPgpPacketPointer != abKeyBytes.Length)) || (_ltSubkeys == null) || (_ltSubkeys.Count == 0))
                    _eStatus = nStatus.ParseErrorRaw;
                else
                {
                    foreach (PgpSignature Subkey in _ltSubkeys)
                        isPublicKey = isPublicKey && (Subkey.PrivateKeyPacket == null);   // one private key packet flags the whole token as private

                    _eType = isPublicKey ? nType.Public : nType.Private;
                }
            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public string sComment
        {
            get { return (_UserIdPacket == null) ? string.Empty : _UserIdPacket.sComment; }
        }

        /// <summary></summary>
        public string sEmail
        {
            get { return (_UserIdPacket == null) ? string.Empty : _UserIdPacket.sEmail; }
        }

        /// <summary></summary>
        public string sFirmwareVersion
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.FirmwareVersion; }
        }

        /// <summary></summary>
        public ulong vFreePrivateMemory
        {
            get { return _TokenInfo == null ? 0 : _TokenInfo.FreePrivateMemory; }
        }

        /// <summary></summary>
        public ulong vFreePublicMemory
        {
            get { return _TokenInfo == null ? 0 : _TokenInfo.FreePublicMemory; }
        }

        /// <summary></summary>
        public string sHardwareVersion
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.HardwareVersion; }
        }

        /// <summary></summary>
        public string sLabel
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.Label; }
        }

        /// <summary></summary>
        public string sManufacturer
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.ManufacturerId; }
        }

        /// <summary></summary>
        public int iMaxPinLength
        {
            get { return _TokenInfo == null ? -1 : (int)_TokenInfo.MaxPinLen; }
        }

        /// <summary></summary>
        public int iMinPinLength
        {
            get { return _TokenInfo == null ? -1 : (int)_TokenInfo.MinPinLen; }
        }

        /// <summary></summary>
        public string sModel
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.Model; }
        }

        /// <summary></summary>
        public string sName
        {
            get { return (_UserIdPacket == null) ? _sSlotName + " (0x" + sSerialNumber + ")" : _UserIdPacket.sName; }
        }

        /// <summary></summary>
        public bool isOnSmartCard
        {
            get { return _TokenInfo != null; }
        }

        /// <summary></summary>
        public string sSerialNumber
        {
            get { return _TokenInfo == null ? string.Empty : _TokenInfo.SerialNumber; }
        }

        /// <summary>Error code.</summary>
        public nStatus eStatus
        {
            get { return _eStatus; }
        }

        /// <summary></summary>
        public List<PgpSignature> ltSubkeys
        {
            get { return _ltSubkeys; }
        }

        /// <summary></summary>
        public ulong vTotalPrivateMemory
        {
            get { return _TokenInfo == null ? 0 : _TokenInfo.TotalPrivateMemory; }
        }

        /// <summary></summary>
        public ulong vTotalPublicMemory
        {
            get { return _TokenInfo == null ? 0 : _TokenInfo.TotalPublicMemory; }
        }

        /// <summary></summary>
        public nType eType
        {
            get { return _eType; }
        }

        /// <summary></summary>
        public string sUserId
        {
            get { return (_UserIdPacket == null) ? string.Empty : _UserIdPacket.sUserId; }
        }

        #endregion

        #region methods

        public void AddPublicKey(ISlotInfo SlotInfo, byte[] abId, PgpKeyFlags.nFlags eKeyFlags, byte[] abModulus, byte[] abExponent)
        {
            PgpSignature NewSignature = new PgpSignature(SlotInfo, abId, eKeyFlags, abModulus, abExponent, _Cryptography);

            if (NewSignature.eStatus == PgpPacketBase.nStatus.OK)
            {
                _eType = nType.Public;
                _sSlotName = NewSignature.PublicKeyPacket.sSlotDescription.Replace("Nitrokey Nitrokey", "Nitrokey").Replace(" 0", "");   // cosmetics
                _ltSubkeys.Add(NewSignature);
                SortSubkeys();
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        public bool Equals(PgpToken Other)
        {
            bool isSameHardwareToken, isSamePgpKeyRing;

            isSameHardwareToken = isSamePgpKeyRing = false;

            if (Other != null)
            {
                isSameHardwareToken = !string.IsNullOrEmpty(sManufacturer) && !string.IsNullOrEmpty(sSerialNumber) && (sManufacturer == Other.sManufacturer) && (sSerialNumber == Other.sSerialNumber);
                isSamePgpKeyRing = (_eType == Other.eType) && (_ltSubkeys != null) && (Other.ltSubkeys != null) && (_ltSubkeys.Count == Other.ltSubkeys.Count);

                if (isSamePgpKeyRing)
                {
                    for (int i = 0; i < _ltSubkeys.Count; i++)
                        isSamePgpKeyRing = isSamePgpKeyRing && _ltSubkeys[i].Equals(Other.ltSubkeys[i]);
                }
            }

            return isSameHardwareToken || isSamePgpKeyRing;
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
                if (Other is PgpToken OtherToken)
                    return Equals(OtherToken);
                else
                    return false;
            }
        }

        /// <summary></summary>
        public override int GetHashCode()
        {
            if ((_ltSubkeys != null) && (_ltSubkeys.Count > 0))
                return _ltSubkeys[0].GetHashCode();
            else
                return (sName + sEmail + sManufacturer + sSerialNumber).GetHashCode();
        }

        /// <summary>Returns the first subkey with the function matching the flag.</summary>
        public PgpSignature GetSubkey(PgpKeyFlags.nFlags eFlag)
        {
            PgpSignature ReturnSubkey = null;

            if (_ltSubkeys != null)
                ReturnSubkey = _ltSubkeys.Find(s => (s.eKeyFlags & eFlag) != 0);

            return ReturnSubkey;
        }

        /// <summary>Returns the first subkey with the fingerprint or key id.</summary>
        public PgpSignature GetSubkey(byte[] abFingerprintOrId)
        {
            bool isEqual;
            PgpSignature ReturnSubkey = null;

            if ((abFingerprintOrId != null) && (abFingerprintOrId.Length >= PgpPacketBase.ciKeyIdLength) && (abFingerprintOrId.Length <= PgpPacketBase.ciSha1FingerprintLength) && (_ltSubkeys != null))
            {
                foreach (PgpSignature Subkey in _ltSubkeys)
                {
                    if (ReturnSubkey == null)
                    {
                        isEqual = (Subkey.abFingerprint != null) && (Subkey.abFingerprint.Length == PgpPacketBase.ciSha1FingerprintLength);

                        if (isEqual)
                        {
                            for (int i = 0; i < abFingerprintOrId.Length; i++)
                                isEqual = isEqual && (abFingerprintOrId[i] == Subkey.abFingerprint[i + PgpPacketBase.ciSha1FingerprintLength - abFingerprintOrId.Length]);
                        }

                        if (isEqual)
                            ReturnSubkey = Subkey;
                    }
                }
            }
            return ReturnSubkey;
        }

        /// <summary>Locks all subkeys and overwrites their secret data.</summary>
        public void Lock()
        {
            if (_ltSubkeys != null)
            {
                foreach (PgpSignature Subkey in _ltSubkeys)
                    Subkey.Lock();
            }
        }

        private PgpPacket ParseCertificationSignature(PgpPacket RawPgpPacket, List<PgpToken> ltTokens)
        {
            PgpSignature ReturnPaket = null;

            if ((RawPgpPacket != null) && (_KeyPacket != null) && (_UserIdPacket != null) && (_Cryptography != null))
            {
                if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateSubkey))
                {
                    ReturnPaket = new PgpSignature(RawPgpPacket, (PgpPrivateKey)_KeyPacket, _UserIdPacket, ltTokens, _Cryptography);

                    if ((_KeyPacket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                        ((PgpPrivateKey)_KeyPacket).PublicKey.Signature = ReturnPaket;
                }
                else if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicSubkey))
                {
                    ReturnPaket = new PgpSignature(RawPgpPacket, (PgpPublicKey)_KeyPacket, _UserIdPacket, ltTokens, _Cryptography);

                    if ((_KeyPacket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                        ((PgpPublicKey)_KeyPacket).Signature = ReturnPaket;
                }
            }                

            return ReturnPaket;
        }

        private PgpPacket ParsePrivateKeyPacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = new PgpPrivateKey(RawPgpPacket, _Cryptography);

            if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK) && ((ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PrivateKey) || (ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PrivateSubkey)))
                _KeyPacket = ReturnPaket;
            else
                _KeyPacket = null;

            return ReturnPaket;
        }

        private PgpPacket ParsePublicKeyPacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = new PgpPublicKey(RawPgpPacket);

            if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK) && ((ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PublicKey) || (ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PublicSubkey)))
                _KeyPacket = ReturnPaket;
            else
                _KeyPacket = null;

            return ReturnPaket;
        }

        private PgpPacket ParseSignaturePacket(PgpPacket RawPgpPacket, List<PgpToken> ltTokens)
        {
            PgpPacket ReturnPaket = null;
            PgpPacketBase.nSignatureType ePreviewSignatureType = (PgpPacketBase.nSignatureType)RawPgpPacket.abRawBytes[RawPgpPacket.iHeaderLength + 1];

            switch (ePreviewSignatureType)
            {
                case PgpPacketBase.nSignatureType.GenericCertification:
                case PgpPacketBase.nSignatureType.PersonaCertification:
                case PgpPacketBase.nSignatureType.CasualCertification:
                case PgpPacketBase.nSignatureType.PositiveCertification: ReturnPaket = ParseCertificationSignature(RawPgpPacket, ltTokens); break;
                case PgpPacketBase.nSignatureType.SubkeyBinding: ReturnPaket = ParseSubkeySignature(RawPgpPacket); break;
            }
                  
            if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                _ltSubkeys.Add((PgpSignature)ReturnPaket);

            return ReturnPaket;
        }

        private PgpPacket ParseSubkeySignature(PgpPacket RawPgpPacket)
        {
            PgpSignature ReturnPaket = null;

            if ((RawPgpPacket != null) && (_ltSubkeys.Count > 0) && (_KeyPacket != null) && (_Cryptography != null))
            {
                if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateSubkey))
                {
                    ReturnPaket = new PgpSignature(RawPgpPacket, _ltSubkeys[0].PublicKeyPacket, (PgpPrivateKey)_KeyPacket, _Cryptography);

                    if ((_KeyPacket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                        ((PgpPrivateKey)_KeyPacket).PublicKey.Signature = ReturnPaket;
                }
                else if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicSubkey))
                {
                    ReturnPaket = new PgpSignature(RawPgpPacket, _ltSubkeys[0].PublicKeyPacket, (PgpPublicKey)_KeyPacket, _Cryptography);

                    if ((_KeyPacket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                        ((PgpPublicKey)_KeyPacket).Signature = ReturnPaket;
                }
            }                

            return ReturnPaket;
        }

        private PgpPacket ParseUserIdPacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = null;

            if (_UserIdPacket == null)
            {
                ReturnPaket = new PgpUserId(RawPgpPacket);

                if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                    _UserIdPacket = (PgpUserId)ReturnPaket;
            }
            return ReturnPaket;
        }

        /// <summary>Sorts subkeys into the usual OpenPGP order: signature key, encryption key, authentication key.</summary>
        public void SortSubkeys()
        {
            IEnumerable<PgpSignature> qySortedSubkeys;

            if (_ltSubkeys != null)
            {
                if (_ltSubkeys.Count == 2)
                {
                    if ((_ltSubkeys[0].eKeyFlags & PgpKeyFlags.nFlags.CertifyOrSign) == 0)
                        _ltSubkeys.Reverse();
                }
                else
                {
                    qySortedSubkeys = from s in _ltSubkeys orderby s.eTranslatedKeyFlags select s;
                    _ltSubkeys = qySortedSubkeys.ToList();
                }
            }
        }

        // public bool Unlock(byte[] abPassphrase) - Deliberately there is no function to unlock all subkeys, use GetSubkey() first.

        #endregion
    }
}
