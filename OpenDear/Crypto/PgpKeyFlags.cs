namespace OpenDear.Crypto
{
    using System;


    public class PgpKeyFlags : PgpSignatureSubpacket
    {
        [Flags]
        public enum nFlags
        {
            None = 0x00,
            Certify = 0x01,
            Sign = 0x02,
            EncryptCommunication = 0x04,
            EncryptStorage = 0x08,
            Encrypt = EncryptCommunication | EncryptStorage,
            SplitPrivate = 0x10,
            Authenticate = 0x20,
            SharedPrivate = 0x80
        }

        private nFlags _eFlags;

        #region constructors

        public PgpKeyFlags(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            _eFlags = nFlags.None;

            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + 2))
                {
                    _eStatus = nStatus.ParseError;
                }
                else
                {
                    eFlags = (nFlags)_abRawBytes[_iHeaderLength + 1];                    
                }
            }
        }

        public PgpKeyFlags(nFlags eFlags) : base()
        {
            _eFlags = eFlags;
        }

        #endregion

        #region properties

        /// <summary></summary>
        public nFlags eFlags
        {
            get { return _eFlags; }
            set { _eFlags = value; }
        }

        #endregion

        #region methods

        #endregion
    }
}
