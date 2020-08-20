namespace OpenDear.Crypto
{
    using System;
    using System.Collections.Generic;
    using Net.Pkcs11Interop.HighLevelAPI;


    public class PgpToken : IEquatable<PgpToken>
    {
        public enum nStatus { OK, ParseErrorRaw, ParseErrorSub, Undefined };
        public enum nType { Private, Public, Symmetric, Undefined };

        private readonly nStatus _eStatus;
        private readonly nType _eType;
        private string _sSlotName;
        private readonly ITokenInfo _TokenInfo;
        private PgpUserId _UserIdPacket;
        private readonly EncryptionServices _Cryptography;
        private PgpPacket _KeyPacket;
        private readonly List<PgpSignature> _ltSubkeys;


        #region constructors

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

        public PgpToken(ITokenInfo TokenInfo, EncryptionServices Cryptography) : this(Cryptography)
        {
            _TokenInfo = TokenInfo;
        }

        public PgpToken(byte[] abKeyBytes, EncryptionServices Cryptography) : this(Cryptography)
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
                            case PgpPacket.nPacketTag.Signature: DecodedPgpPacket = ParseSignaturePacket(RawPgpPacket); break;
                            case PgpPacket.nPacketTag.UserId: DecodedPgpPacket = ParseUserIdPacket(RawPgpPacket); break;
                            default: DecodedPgpPacket = null; Console.WriteLine("not implemented: ePacketTag=" + RawPgpPacket.ePacketTag.ToString()); break;
                        }
                        if ((DecodedPgpPacket == null) || (DecodedPgpPacket.eStatus != PgpPacketBase.nStatus.OK))
                            _eStatus = nStatus.ParseErrorSub;
                        else
                            Console.WriteLine("   Found ePacketTag=" + RawPgpPacket.ePacketTag.ToString() + " iHeaderLength=" + RawPgpPacket.iHeaderLength.ToString() + ", iDataLength=" + RawPgpPacket.iDataLength.ToString());
                        
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

        #endregion

        #region methods

        public void AddPublicKey(ISlotInfo SlotInfo, byte[] abId, PgpKeyFlags.nFlags eKeyFlags, byte[] abModulus, byte[] abExponent)
        {
            PgpPublicKey NewPublicKey;
            // PgpSignature NewSignature;

            NewPublicKey = new PgpPublicKey(SlotInfo, abId, eKeyFlags, abModulus, abExponent)
            {
                // Signature = NewSignature = new PgpSignature(eKeyFlags)
            };

            _sSlotName = NewPublicKey.sSlotDescription.Replace("Nitrokey Nitrokey", "Nitrokey").Replace(" 0", "");   // cosmetics
            // _ltPackets.Add(NewPublicKey);
            // _ltPackets.Add(NewSignature);
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

        private PgpPacket ParsePrivateKeyPacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = null;

            if (_KeyPacket == null)
            {
                ReturnPaket = new PgpPrivateKey(RawPgpPacket, _Cryptography);

                if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK) && ((ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PrivateKey) || (ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PrivateSubkey)))
                    _KeyPacket = ReturnPaket;
            }
            return ReturnPaket;
        }

        private PgpPacket ParsePublicKeyPacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = null;

            if (_KeyPacket == null)
            {
                ReturnPaket = new PgpPublicKey(RawPgpPacket);

                if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK) && ((ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PublicKey) || (ReturnPaket.ePacketTag == PgpPacket.nPacketTag.PublicSubkey)))
                    _KeyPacket = ReturnPaket;
            }
            return ReturnPaket;
        }

        private PgpPacket ParseSignaturePacket(PgpPacket RawPgpPacket)
        {
            PgpPacket ReturnPaket = null;

            if (_KeyPacket != null)
            {
                if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PrivateSubkey))
                {
                    if (_ltSubkeys.Count == 0)
                        ReturnPaket = new PgpSignature(RawPgpPacket, (PgpPrivateKey)_KeyPacket, _UserIdPacket, _Cryptography);
                    else
                        ReturnPaket = new PgpSignature(RawPgpPacket, _ltSubkeys[0].PublicKeyPacket, (PgpPrivateKey)_KeyPacket, _Cryptography);
                }
                else if ((_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicKey) || (_KeyPacket.ePacketTag == PgpPacket.nPacketTag.PublicSubkey))
                {
                    if (_ltSubkeys.Count == 0)
                        ReturnPaket = new PgpSignature(RawPgpPacket, (PgpPublicKey)_KeyPacket, _UserIdPacket, _Cryptography);
                    else
                        ReturnPaket = new PgpSignature(RawPgpPacket, _ltSubkeys[0].PublicKeyPacket, (PgpPublicKey)_KeyPacket, _Cryptography);
                }
                   
                if ((ReturnPaket != null) && (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK))
                    _ltSubkeys.Add((PgpSignature)ReturnPaket);

                _KeyPacket = null;
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

        #endregion
    }
}
