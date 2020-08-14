namespace OpenDear.Crypto
{
    using System;


    public class PgpPublicKeyEncryptedKey : PgpPacket
    {
        #region constructors

        private int _iVersion;
        private byte[] _abPublicKeyId;


        public PgpPublicKeyEncryptedKey(PgpPacket FromPacket) : base(FromPacket)
        {
            int i;

            if (_eStatus == nStatus.OK)
            {
                _iVersion =_abRawBytes[0];
                _abPublicKeyId = new Byte[ciKeyIdLength];
                for (i = 0; i < ciKeyIdLength; i++)
                    _abPublicKeyId[i] = _abRawBytes[i + 1];

            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abPublicKeyId
        {
            get { return _abPublicKeyId; }
        }

        /// <summary></summary>
        public int iVersion
        {
            get { return _iVersion; }
        }

        #endregion

        #region methods

        #endregion
    }
}
