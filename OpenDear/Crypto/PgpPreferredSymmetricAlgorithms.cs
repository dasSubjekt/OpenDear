namespace OpenDear.Crypto
{
    using System;


    public class PgpPreferredSymmetricAlgorithms : PgpSignatureSubpacket
    {
        #region constructors

        public PgpPreferredSymmetricAlgorithms(PgpSignatureSubpacket FromPacket) : base(FromPacket)
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
