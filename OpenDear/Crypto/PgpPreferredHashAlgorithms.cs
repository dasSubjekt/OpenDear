namespace OpenDear.Crypto
{
    using System;


    public class PgpPreferredHashAlgorithms : PgpSignatureSubpacket
    {
        #region constructors

        public PgpPreferredHashAlgorithms(PgpSignatureSubpacket FromPacket) : base(FromPacket)
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
