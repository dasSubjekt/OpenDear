namespace OpenDear.Crypto
{
    using System;


    public class PgpFeatures : PgpSignatureSubpacket
    {
        #region constructors

        public PgpFeatures(PgpSignatureSubpacket FromPacket) : base(FromPacket)
        {
            if (_eStatus == nStatus.OK)
            {

            }
        }

        #endregion

        #region properties

        #endregion

        #region methods

        #endregion
    }
}
