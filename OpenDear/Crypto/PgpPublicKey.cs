namespace OpenDear.Crypto
{
    using System;
    using System.Security.Cryptography;
    using Net.Pkcs11Interop.HighLevelAPI;


    /// <summary>Implements RFC 4880 section 5.5.2. Public-Key Packet Formats.</summary>
    public class PgpPublicKey : PgpPacket
    {
        private byte[] _abId;
        private int _iModulusBits, _iExponentBits;
        private DateTime _Created;
        private ISlotInfo _SlotInfo;
        private PgpSignature _Signature;
        private nPublicKeyAlgorithm _ePublicKeyAlgorithm;
        private RSAParameters _KeyParameters;

        #region constructors

        protected PgpPublicKey(nPacketTag ePacketTag) : base(ePacketTag)
        {
            Initialise();
        }

        public PgpPublicKey(ISlotInfo SlotInfo, byte[] abId, PgpKeyFlags.nFlags eKeyFlags, byte[] abModulus, byte[] abExponent) : this (nPacketTag.PublicKey)
        {
            if ((SlotInfo == null) || (abId == null) || (abModulus == null) || (abExponent == null))
            {
                _eStatus = nStatus.MissingArgument;
            }
            else
            {
                _SlotInfo = SlotInfo;
                _abId = abId;
                _ePacketTag = (eKeyFlags & PgpKeyFlags.nFlags.Sign) == 0 ? nPacketTag.PublicSubkey : nPacketTag.PublicKey;
                InitialiseKeyParameters(abModulus, abExponent);

                // Console.WriteLine("eKeyFlags=" + eKeyFlags.ToString() + ", iModulusBits=" + _iModulusBits.ToString() + ", iPublicExponentBits=" + _iPublicExponentBits.ToString());
            }
        }

        public PgpPublicKey(PgpPacket FromPacket) : base(FromPacket)
        {
            PgpPublicKeyUtility KeyUtility;

            Initialise();
            KeyUtility = new PgpPublicKeyUtility(_abRawBytes);
            _eStatus = KeyUtility.eStatus;

            if (_eStatus == nStatus.OK)
            {
                _Created = KeyUtility.Created;
                _ePublicKeyAlgorithm = KeyUtility.ePublicKeyAlgorithm;
                InitialiseKeyParameters(KeyUtility.abModulus, KeyUtility.abExponent);

                Console.WriteLine("iModulusBits=" + _iModulusBits.ToString() + " | " + KeyUtility.iModulusBits.ToString());
                Console.WriteLine("iExponentBits=" + _iExponentBits.ToString() + " | " + KeyUtility.iExponentBits.ToString());
                Console.WriteLine("abRawBytes.Length=" + _abRawBytes.Length.ToString() + " | " + KeyUtility.abRawBytes.Length.ToString());
            }
        }

        // public PgpPublicKey(nPacketTag ePacketTag, DateTime Created, nPublicKeyAlgorithm ePublicKeyAlgorithm, byte[] abModulus, byte[] abExponent) : this(ePacketTag)
        // {
        //     _Created = Created;
        //     _ePublicKeyAlgorithm = ePublicKeyAlgorithm;
        //     InitialiseKeyParameters(abModulus, abExponent);
        //     Console.WriteLine("new PgpPublicKey() " + _ePacketTag.ToString());
        //     EncodeRawBytes();
        // }

        #endregion

        #region properties

        public DateTime Created
        {
            get { return _Created; }
        }

        public int iExponentBits
        {
            get { return _iExponentBits; }
        }

        public byte[] abId
        {
            get { return _abId; }
        }

        public PgpKeyFlags.nFlags eKeyFlags
        {
            get { return _Signature == null ? PgpKeyFlags.nFlags.None : _Signature.eKeyFlags; }
        }

        public RSAParameters KeyParameters
        {
            get { return _KeyParameters; }
        }

        public int iModulusBits
        {
            get { return _iModulusBits; }
        }

        public nPublicKeyAlgorithm ePublicKeyAlgorithm
        {
            get { return _ePublicKeyAlgorithm; }
        }

        public PgpSignature Signature
        {
            get { return _Signature; }
            set { _Signature = value; }
        }

        /// <summary></summary>
        public string sSlotDescription
        {
            get { return _SlotInfo == null ? string.Empty : _SlotInfo.SlotDescription; }
        }

        /// <summary></summary>
        public string sSlotFirmwareVersion
        {
            get { return _SlotInfo == null ? string.Empty : _SlotInfo.FirmwareVersion; }
        }

        /// <summary></summary>
        public string sSlotHardwareVersion
        {
            get { return _SlotInfo == null ? string.Empty : _SlotInfo.HardwareVersion; }
        }

        /// <summary></summary>
        public ulong vSlotId
        {
            get { return _SlotInfo == null ? 0 : _SlotInfo.SlotId; }
        }

        /// <summary></summary>
        public string sSlotManufacturer
        {
            get { return _SlotInfo == null ? string.Empty : _SlotInfo.ManufacturerId; }
        }

        #endregion

        #region methods

        public override void EncodeRawBytes()
        {
            PgpPublicKeyUtility KeyUtility = new PgpPublicKeyUtility(_ePacketTag, _Created, _ePublicKeyAlgorithm, _KeyParameters.Modulus, _KeyParameters.Exponent);

            if (KeyUtility.eStatus == nStatus.OK)
            {
                _abRawBytes = KeyUtility.abRawBytes;
                _iDataLength = KeyUtility.iDataLength;
                _iHeaderLength = KeyUtility.iHeaderLength;

                Console.WriteLine("iModulusBits=" + _iModulusBits.ToString() + " | " + KeyUtility.iModulusBits.ToString());
                Console.WriteLine("iExponentBits=" + _iExponentBits.ToString() + " | " + KeyUtility.iExponentBits.ToString());
                Console.WriteLine("abRawBytes.Length=" + _abRawBytes.Length.ToString() + " | " + KeyUtility.abRawBytes.Length.ToString());
            }
            else throw new FormatException("PgpPublicKey.EncodeRawBytes()");
        }

        private void Initialise()
        {
            _abId = null;
            _iModulusBits = _iExponentBits = 0;
            _Created = DateTime.UtcNow;
            _SlotInfo = null;
            _Signature = null;
            _ePublicKeyAlgorithm = nPublicKeyAlgorithm.RsaEncryptOrSign;
            _KeyParameters = new RSAParameters();
        }

        private void InitialiseKeyParameters(byte[] abModulus, byte[] abExponent)
        {
            _iModulusBits = CountUsedBits(abModulus);
            _iExponentBits = CountUsedBits(abExponent);
            _KeyParameters.Modulus = abModulus;
            _KeyParameters.Exponent = abExponent;
        }
        #endregion
    }
}
