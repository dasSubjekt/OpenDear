namespace OpenDear.Crypto
{
    using System;
    using System.Collections.Generic;


    public class PgpMessage
    {
        public enum nStatus { OK, ParseErrorRaw, ParseErrorSub, Undefined };

        private readonly nStatus _eStatus;
        private readonly EncryptionServices _Cryptography;
        private readonly List<PgpPublicKeyEncryptedKey> _ltPublicKeyEncryptedKeys;


        #region constructors

        private PgpMessage(EncryptionServices Cryptography)
        {
            _eStatus = nStatus.Undefined;
            _Cryptography = Cryptography;
            _ltPublicKeyEncryptedKeys = new List<PgpPublicKeyEncryptedKey>();
        }

        public PgpMessage(byte[] abMessageBytes, EncryptionServices Cryptography) : this(Cryptography)
        {
            int iPgpPacketPointer = 0;
            PgpPacket DecodedPgpPacket, RawPgpPacket;

            if (abMessageBytes != null)
            {
                _eStatus = nStatus.OK;

                while ((_eStatus == nStatus.OK) && (iPgpPacketPointer < abMessageBytes.Length - 2))
                {
                    RawPgpPacket = new PgpPacket(abMessageBytes, iPgpPacketPointer);
                    if (RawPgpPacket.eStatus == PgpPacketBase.nStatus.OK)
                    {
                        switch (RawPgpPacket.ePacketTag)
                        {
                            case PgpPacket.nPacketTag.PublicKeyEncryptedKey: DecodedPgpPacket = ParsePublicKeyEncryptedKeyPacket(RawPgpPacket); break;
                            case PgpPacket.nPacketTag.SymmetricallyEncryptedProtected: DecodedPgpPacket = new PgpSymmetricallyEncryptedDataPacket(RawPgpPacket); break;
                            default: DecodedPgpPacket = null; Console.WriteLine("not implemented: ePacketTag=" + RawPgpPacket.ePacketTag.ToString()); break;
                        }
                        if ((DecodedPgpPacket == null) || (DecodedPgpPacket.eStatus != PgpPacketBase.nStatus.OK))
                            _eStatus = nStatus.ParseErrorSub;

                        iPgpPacketPointer += (RawPgpPacket.iHeaderLength + RawPgpPacket.iPartialHeaders + RawPgpPacket.iDataLength);
                    }
                    else
                        _eStatus = nStatus.ParseErrorRaw;
                }
            }

            if (((_eStatus == nStatus.OK) && (iPgpPacketPointer != abMessageBytes.Length)))
                _eStatus = nStatus.ParseErrorRaw;
        }

        #endregion

        #region properties

        /// <summary>Error code.</summary>
        public nStatus eStatus
        {
            get { return _eStatus; }
        }

        /// <summary></summary>
        public List<PgpPublicKeyEncryptedKey> ltPublicKeyEncryptedKeys
        {
            get { return _ltPublicKeyEncryptedKeys; }
        }

        #endregion

        #region methods

        /// <summary></summary>
        public void MatchPublicKeys(List<PgpToken> ltTokens)
        {
            PgpSignature Subkey;

            if (ltTokens != null)
            {
                foreach (PgpToken Token in ltTokens)
                {
                    foreach (PgpPublicKeyEncryptedKey WrappedKey in _ltPublicKeyEncryptedKeys)
                    {
                        if (WrappedKey.MatchedPublicKey == null)
                        {
                            Subkey = Token.GetSubkey(WrappedKey.abPublicKeyId);
                            WrappedKey.sUserId = Token.sUserId;
                            WrappedKey.MatchedPublicKey = Subkey;
                        }
                    }
                }
            }
        }

        /// <summary></summary>
        private PgpPacket ParsePublicKeyEncryptedKeyPacket(PgpPacket RawPgpPacket)
        {
            PgpPublicKeyEncryptedKey ReturnPaket = new PgpPublicKeyEncryptedKey(RawPgpPacket);

            if (ReturnPaket.eStatus == PgpPacketBase.nStatus.OK)
                _ltPublicKeyEncryptedKeys.Add(ReturnPaket);

            return ReturnPaket;
        }

        #endregion
    }
}
