namespace OpenDear.Crypto
{
    using System;


    public class PgpCreationTime : PgpSignatureSubpacket
    {
        private DateTime _Created;

        #region constructors

        public PgpCreationTime(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + 5))
                    _eStatus = nStatus.ParseError;
                else
                    _Created = GetDateAt(_iHeaderLength + 1);
            }
        }

        #endregion

        #region properties

        public DateTime Created
        {
            get { return _Created; }
        }

        #endregion

        #region methods

        #endregion
    }
}
