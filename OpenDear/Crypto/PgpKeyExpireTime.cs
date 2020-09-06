namespace OpenDear.Crypto
{
    using System;


    public class PgpKeyExpireTime : PgpSignatureSubpacket
    {
        private uint _uSecondsValid;

        #region constructors

        public PgpKeyExpireTime(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            _uSecondsValid = 0;

            if (_eStatus == nStatus.OK)
            {
                if ((_abRawBytes == null) || (_abRawBytes.Length != _iHeaderLength + 5))
                    _eStatus = nStatus.ParseError;
                else
                    _uSecondsValid = ((uint)_abRawBytes[_iHeaderLength + 1] << 24) | ((uint)_abRawBytes[_iHeaderLength + 2] << 16) | ((uint)_abRawBytes[_iHeaderLength + 3] << 8) | (uint)_abRawBytes[_iHeaderLength + 4];
            }
        }

        #endregion

        #region properties

        public uint uSecondsValid
        {
            get { return _uSecondsValid; }
        }

        #endregion

        #region methods

        #endregion
    }
}
