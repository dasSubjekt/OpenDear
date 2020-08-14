namespace OpenDear.Crypto
{
    using System;


    public class PgpRevocationReason : PgpSignatureSubpacket
    {
        private nRevocationReason _eReason;

        #region constructors

        public PgpRevocationReason(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + 2))
                {
                    _eStatus = nStatus.ParseError;
                }
                else
                {
                    _eReason = (nRevocationReason)_abRawBytes[_iHeaderLength + 1];
                }
            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public nRevocationReason eReason
        {
            get { return _eReason; }
        }

        #endregion

        #region methods

        #endregion
    }
}
