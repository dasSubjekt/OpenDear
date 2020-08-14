namespace OpenDear.Crypto
{
    using System;


    public class PgpKeyServerPreferences : PgpSignatureSubpacket
    {
        #region constructors

        public PgpKeyServerPreferences(PgpSignatureSubpacket FromPacket) : base(FromPacket)
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
