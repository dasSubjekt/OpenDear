namespace OpenDear.Crypto
{
    using System;


    /// <summary>Implements RFC 4880 section 4. Packet Syntax.</summary>
    public class PgpPacket : PgpPacketBase
    {
        protected const byte cbPacketTagMask = 0x80;
        protected const byte cbNewPacketFormatMask = 0x40;
        protected const byte cbNewPacketFormatPacketTagMask = 0x3f;
        protected const byte cbOldPacketFormatPacketTagMask = 0x3c;
        protected const byte cbOldPacketFormatLengthTypeMask = 0x03;
        protected const byte cbOldPacketFormatLengthOneByte = 0x00;
        protected const byte cbOldPacketFormatLengthTwoBytes = 0x01;
        protected const byte cbOldPacketFormatLengthFourBytes= 0x02;
        protected const byte cbOldPacketFormatLengthIndeterminate = 0x03;
        protected const int ciKeyIdLength = 8;


        /// <remarks>RFC 4880 section 4.3. Packet tag numbers.</remarks>
        public enum nPacketTag { Reserved = 0, PublicKeyEncryptedKey = 1, Signature = 2, SymmetricKeyEncryptedKey = 3, OnePassSignature = 4,
                                 PrivateKey = 5, PublicKey = 6, PrivateSubkey = 7, CompressedData = 8, SymmetricallyEncryptedUnprotected = 9, Marker = 10, LiteralData = 11,
                                 Trust = 12, UserId = 13, PublicSubkey = 14, UserAttribute = 17, SymmetricallyEncryptedProtected = 18, 
                                 ModificationDetectionCode = 19, Experimental1 = 60, Experimental2 = 61, Experimental3 = 62, Experimental4 = 63 };


        protected bool _isNewPacketFormat;
        protected nPacketTag _ePacketTag;
        protected int _iPartialHeaders;

        #region constructors

        protected PgpPacket(nPacketTag ePacketTag) : base()
        {
            _isNewPacketFormat = false;
            _ePacketTag = ePacketTag;
            _iPartialHeaders = 0;
        }

        protected PgpPacket(PgpPacket FromPacket) : base(FromPacket)
        {
            _isNewPacketFormat = FromPacket.isNewPacketFormat;
            _ePacketTag = FromPacket.ePacketTag;
            _iPartialHeaders = FromPacket.iPartialHeaders;
        }

        public PgpPacket(byte[] abPaketBytes, int iOffset) : this(nPacketTag.Reserved)
        {
            byte bLengthByte, bPacketTag;
            bool isPartialLength;
            int i, j, k, iPacketType, iPartialDataLength = 0;
            int[] aiNewPartialHeaderOffsets, aiPartialHeaderOffsets = null;

            if ((abPaketBytes == null) || (iOffset >= abPaketBytes.Length - 4))
            {
                _eStatus = nStatus.ParseError;
            }
            else
            {
                bPacketTag = abPaketBytes[iOffset];
                if ((bPacketTag & cbPacketTagMask) == 0)
                {
                    _eStatus = nStatus.InvalidPacketTag;
                }
                else
                {
                    _eStatus = nStatus.OK;
                    _isNewPacketFormat = ((bPacketTag & cbNewPacketFormatMask) != 0);

                    do
                    {
                        isPartialLength = false;
                        if (_isNewPacketFormat)
                        {
                            iPacketType = (bPacketTag & cbNewPacketFormatPacketTagMask);

                            if (iOffset + iPartialDataLength + 6 > abPaketBytes.Length)
                            {
                                bLengthByte = 0;
                                _eStatus = nStatus.ParseError;
                            }
                            else
                                bLengthByte = abPaketBytes[iOffset + iPartialDataLength + 1];

                            if (bLengthByte < cbSmallestTwoByteLengthNew)
                            {
                                _iDataLength = bLengthByte;
                                _iHeaderLength = 2;
                            }
                            else if (bLengthByte < 0xe0)
                            {
                                _iDataLength = ((bLengthByte - cbSmallestTwoByteLengthNew) << 8) + abPaketBytes[iOffset + iPartialDataLength + 2] + cbSmallestTwoByteLengthNew;
                                _iHeaderLength = 3;
                            }
                            else if (bLengthByte == 0xff)
                            {
                                _iDataLength = abPaketBytes[iOffset + iPartialDataLength + 2] << 24 | abPaketBytes[iOffset + iPartialDataLength + 3] << 16 | abPaketBytes[iOffset + iPartialDataLength + 4] << 8 | abPaketBytes[iOffset + iPartialDataLength + 5];
                                _iHeaderLength = 6;
                            }
                            else
                            {
                                isPartialLength = true;
                                _iDataLength = 1 << (bLengthByte & 0x1f);

                                if (aiPartialHeaderOffsets == null)
                                {
                                    aiPartialHeaderOffsets = new int[1];
                                }
                                else
                                {
                                    aiNewPartialHeaderOffsets = new int[aiPartialHeaderOffsets.Length + 1];
                                    for (i = 0; i < aiPartialHeaderOffsets.Length; i++)
                                        aiNewPartialHeaderOffsets[i] = aiPartialHeaderOffsets[i];
                                    aiPartialHeaderOffsets = aiNewPartialHeaderOffsets;
                                }
                                aiPartialHeaderOffsets[aiPartialHeaderOffsets.Length - 1] = iPartialDataLength;
                            }
                        }
                        else
                        {
                            iPacketType = (bPacketTag & cbOldPacketFormatPacketTagMask) >> 2;
                            switch (bPacketTag & cbOldPacketFormatLengthTypeMask)
                            {
                                case cbOldPacketFormatLengthOneByte: _iDataLength = abPaketBytes[iOffset + iPartialDataLength + 1]; _iHeaderLength = 2; break;
                                case cbOldPacketFormatLengthTwoBytes: _iDataLength = abPaketBytes[iOffset + iPartialDataLength + 1] << 8 | abPaketBytes[iOffset + iPartialDataLength + 2]; _iHeaderLength = 3; break;
                                case cbOldPacketFormatLengthFourBytes: _iDataLength = abPaketBytes[iOffset + iPartialDataLength + 1] << 24 | abPaketBytes[iOffset + iPartialDataLength + 2] << 16 | abPaketBytes[iOffset + iPartialDataLength + 3] << 8 | abPaketBytes[iOffset + iPartialDataLength + 4]; _iHeaderLength = 5; break;
                                default: _iDataLength = -1; _eStatus = nStatus.IndeterminateLengthNotSupported; break;
                            }
                        }

                        if (isPartialLength)
                            iPartialDataLength += (1 + _iDataLength);

                    } while (isPartialLength);

                    if ((_iDataLength < 0) || (_eStatus != nStatus.OK) || (iOffset + iPartialDataLength + _iHeaderLength + _iDataLength > abPaketBytes.Length))
                    {
                        if (_eStatus == nStatus.OK)
                            _eStatus = nStatus.ParseError;
                    }
                    else
                    {
                        switch (iPacketType)
                        {
                            case 1: _ePacketTag = nPacketTag.PublicKeyEncryptedKey; break;
                            case 2: _ePacketTag = nPacketTag.Signature; break;
                            case 5: _ePacketTag = nPacketTag.PrivateKey; break;
                            case 6: _ePacketTag = nPacketTag.PublicKey; break;
                            case 7: _ePacketTag = nPacketTag.PrivateSubkey; break;
                            case 13: _ePacketTag = nPacketTag.UserId; break;
                            case 14: _ePacketTag = nPacketTag.PublicSubkey; break;
                            case 18: _ePacketTag = nPacketTag.SymmetricallyEncryptedProtected; break;
                            default: _eStatus = nStatus.ParseError; break;
                        }
                    }
                }
            }

            if (_eStatus == nStatus.OK)
            {
                if (aiPartialHeaderOffsets == null)
                {
                    _abRawBytes = new byte[_iHeaderLength + _iDataLength];
                    for (i = 0; i < _iHeaderLength + _iDataLength; i++)
                        _abRawBytes[i] = abPaketBytes[iOffset + i];
                }
                else  // TODO correct for handling of _iHeaderLength
                {
                    _iPartialHeaders = aiPartialHeaderOffsets.Length;
                    _abRawBytes = new byte[iPartialDataLength + _iDataLength - _iPartialHeaders];
                    j = k = 0;
                    for (i = 0; i < iPartialDataLength; i++)
                    {
                        if ((j < aiPartialHeaderOffsets.Length) && (aiPartialHeaderOffsets[j] == i))
                            j++;
                        else
                            _abRawBytes[k++] = abPaketBytes[iOffset + i + 1];
                    }
                    for (i = 0; i < _iDataLength; i++)
                        _abRawBytes[k++] = abPaketBytes[iOffset + iPartialDataLength + _iHeaderLength + i];
                    _iDataLength = _abRawBytes.Length;

                    // for (i = 0; i < _abRawBytes.Length; i++)
                    //     Console.Write(_abRawBytes[i].ToString("x2") + " ");
                    // Console.WriteLine();
                }
            }
        }

        #endregion

        #region properties

        /// <summary></summary>
        public bool isNewPacketFormat
        {
            get { return _isNewPacketFormat; }
        }

        /// <summary></summary>
        public nPacketTag ePacketTag
        {
            get { return _ePacketTag; }
        }

        /// <summary></summary>
        public int iPartialHeaders
        {
            get { return _iPartialHeaders; }
        }
        #endregion

        #region methods

        protected byte[] EncodeHeaderBytes(long kBodyLength, bool isPartialLength = false)
        {
            byte bPacketTag;
            byte[] abReturn, abTemp = new byte[6];

            if (kBodyLength > UInt32.MaxValue)
            {
                throw new NotImplementedException("Partial headers are not yet implemented in PgpPacket.EncodeHeaderBytes().");
                // abReturn = EncodeHeaderBytes(0, true);
                // this.partialBufferLength = 1 << BufferSizePower;
                // this.partialBuffer = new byte[partialBufferLength];
                // this.partialPower = BufferSizePower;
                // this.partialOffset = 0;
            }
            else if (_isNewPacketFormat)
            {
                abTemp[0] = (byte)(cbPacketTagMask | cbNewPacketFormatMask | (int)_ePacketTag);

                if (isPartialLength)   // first byte in the range of 0xe0 ... 0xfe
                {
                    throw new NotImplementedException("Partial headers are not yet implemented in PgpPacket.EncodeHeaderBytes().");
                }
                else
                {
                    _iDataLength = (int)kBodyLength;

                    if (kBodyLength < cbSmallestTwoByteLengthNew)   // 6 bits for body length
                    {
                        abTemp[1] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 2;
                    }
                    else if (kBodyLength < 0x2000L + cbSmallestTwoByteLengthNew)   // 5 + 8 bits for body length
                    {
                        kBodyLength -= cbSmallestTwoByteLengthNew;
                        abTemp[1] = (byte)(((kBodyLength >> 8) & 0xff) + cbSmallestTwoByteLengthNew);   // range of 0xc0 ... 0xdf
                        abTemp[2] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 3;
                    }
                    else
                    {
                        abTemp[1] = 0xff;
                        abTemp[2] = (byte)((kBodyLength >> 24) & 0xff);
                        abTemp[3] = (byte)((kBodyLength >> 16) & 0xff);
                        abTemp[4] = (byte)((kBodyLength >> 8) & 0xff);
                        abTemp[5] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 6;
                    }
                }
            }
            else
            {
                bPacketTag = (byte)(cbPacketTagMask | ((int)_ePacketTag << 2));

                if (isPartialLength)
                {
                    abTemp[0] = (byte)(bPacketTag | cbOldPacketFormatLengthIndeterminate);
                    _iHeaderLength = 1;
                }
                else
                {
                    _iDataLength = (int)kBodyLength;

                    if (kBodyLength < 0x0100L)
                    {
                        abTemp[0] = (byte)(bPacketTag | cbOldPacketFormatLengthOneByte);
                        abTemp[1] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 2;
                    }
                    else if (kBodyLength < 0x010000L)
                    {
                        abTemp[0] = (byte)(bPacketTag | cbOldPacketFormatLengthTwoBytes);
                        abTemp[1] = (byte)((kBodyLength >> 8) & 0xff);
                        abTemp[2] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 3;
                    }
                    else
                    {
                        abTemp[0] = (byte)(bPacketTag | cbOldPacketFormatLengthFourBytes);
                        abTemp[1] = (byte)((kBodyLength >> 24) & 0xff);
                        abTemp[2] = (byte)((kBodyLength >> 16) & 0xff);
                        abTemp[3] = (byte)((kBodyLength >> 8) & 0xff);
                        abTemp[4] = (byte)(kBodyLength & 0xff);
                        _iHeaderLength = 5;
                    }
                }
            }

            abReturn = new byte[_iHeaderLength];
            for (int i = 0; i < _iHeaderLength; i++)
                abReturn[i] = abTemp[i];

            return abReturn;
        }

        public override void EncodeRawBytes()
        {
            throw new NotImplementedException("The method PgpPacket.EncodeRawBytes() must be overwritten in each derived class.");
        }

        #endregion
    }
}
