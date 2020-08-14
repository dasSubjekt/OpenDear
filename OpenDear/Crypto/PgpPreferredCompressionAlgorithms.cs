namespace OpenDear.Crypto
{
    using System;


    public class PgpPreferredCompressionAlgorithms : PgpSignatureSubpacket
    {
        #region constructors

        public PgpPreferredCompressionAlgorithms(PgpSignatureSubpacket FromPacket) : base(FromPacket)
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
