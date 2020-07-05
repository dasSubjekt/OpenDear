namespace OpenDear.Model
{
    using System;
    using System.Text;


    /// <summary>A very large positive decimal integer number, inspired by the InfInt project <see cref="https://github.com/sercantutar/infint"/>.</summary>
    public class DecimalInt : IEquatable<DecimalInt>
    {
        private byte[] _abBytes;

        #region constructors

        /// <summary></summary>
        /// <param name=""></param>
        public DecimalInt(byte bDigit)
        {
            if (bDigit > 9)
                throw new FormatException("'" + bDigit.ToString() + "' is not a decimal digit.");
            else
            {
                _abBytes = new byte[1];
                _abBytes[0] = bDigit;
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        public DecimalInt(byte[] abHexadecimalValue) : this("0")
        {
            byte bByte;
            int i, j;

            if (abHexadecimalValue == null)
                throw new ArgumentNullException("abHexadecimalValue must not be null in constructor DecimalInt().");
            else
            {
                for (i = 0; i < abHexadecimalValue.Length; i++)
                {
                    bByte = abHexadecimalValue[i];
                    for (j = 0; j < 8; j++)
                    {
                        DoubleThis();
                        isOdd = ((bByte & 0x80) == 0x80);
                        bByte <<= 1;
                    }
                }
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        public DecimalInt(int iLength)
        {
            _abBytes = new byte[iLength];
            for (int i = 0; i < iLength; i++)
                _abBytes[i] = 0;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public DecimalInt(string sValue)
        {
            bool isError = false;
            char c;

            if (string.IsNullOrEmpty(sValue))
                throw new ArgumentNullException("Argument required in DecimalInt(string sValue).");
            else
            {
                _abBytes = new byte[sValue.Length];

                for (int i = 0; i < sValue.Length; i++)
                {
                    c = sValue[sValue.Length - i - 1];
                    if ((c >= '0') && (c <= '9'))
                        _abBytes[i] = (byte)(c - '0');
                    else
                        isError = true;
                }
                if (isError)
                    throw new FormatException("'" + sValue + "' is not a decimal integer number.");
                else
                    TrimLeadingZeros();
            }
        }
        #endregion

        #region operators

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator ==(DecimalInt First, DecimalInt Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return Equals(First, Second);
            else
                return First.Equals(Second);
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator !=(DecimalInt First, DecimalInt Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return !Equals(First, Second);
            else
                return !(First.Equals(Second));
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator <(DecimalInt First, DecimalInt Second)
        {
            if (First.Length == Second.Length)
                return FirstByteDifference(First, Second) < 0;
            else
               return First.Length < Second.Length;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator <=(DecimalInt First, DecimalInt Second)
        {
            if (First.Length == Second.Length)
                return FirstByteDifference(First, Second) <= 0;
            else
                return First.Length < Second.Length;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator >(DecimalInt First, DecimalInt Second)
        {
            if (First.Length == Second.Length)
                return FirstByteDifference(First, Second) > 0;
            else
                return First.Length > Second.Length;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator >=(DecimalInt First, DecimalInt Second)
        {
            if (First.Length == Second.Length)
                return FirstByteDifference(First, Second) >= 0;
            else
                return First.Length > Second.Length;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static DecimalInt operator +(DecimalInt Summand1, DecimalInt Summand2)
        {
            int iDigit, iCarry = 0;
            DecimalInt Sum = new DecimalInt(Summand1.Length > Summand2.Length ? Summand1.Length + 1 : Summand2.Length + 1);

            for (int i = 0; i < Sum.Length; i++)
            {
                iDigit = (i < Summand1.Length ? Summand1.abBytes[i] : 0) + (i < Summand2.Length ? Summand2.abBytes[i] : 0) + iCarry;
                if (iDigit > 9)
                {
                    iCarry = 1;
                    Sum.abBytes[i] = (byte)(iDigit - 10);
                }
                else
                {
                    iCarry = 0;
                    Sum.abBytes[i] = (byte)iDigit;
                }
            }
            Sum.TrimLeadingZeros();
            return Sum;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static DecimalInt operator -(DecimalInt Minuend, DecimalInt Subtrahend)
        {
            int iDigit, iCarry = 0;
            DecimalInt Difference;

            if (Minuend < Subtrahend)
                throw new NotImplementedException("Computing with negative numbers is not implemented.");
            else
            {
                Difference = new DecimalInt(Minuend.Length);
                for (int i = 0; i < Difference.Length; i++)
                {
                    iDigit = Minuend.abBytes[i] - (i < Subtrahend.Length ? Subtrahend.abBytes[i] : 0) - iCarry;
                    if (iDigit < 0)
                    {
                        iCarry = 1;
                        Difference.abBytes[i] = (byte)(iDigit + 10);
                    }
                    else
                    {
                        iCarry = 0;
                        Difference.abBytes[i] = (byte)iDigit;
                    }
                }
                Difference.TrimLeadingZeros();
            }
            return Difference;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static DecimalInt operator *(DecimalInt Factor1, DecimalInt Factor2)
        {
            bool isStayInLoop;
            int iCarry, iDigit, iQuotient, iProduct;
            DecimalInt Product = new DecimalInt(Factor1.Length + Factor2.Length);

            iCarry = iDigit = 0;
            do
            {
                iQuotient = iCarry / 10;
                Product.abBytes[iDigit] = (byte)(iCarry - 10 * iQuotient);
                iCarry = iQuotient;

                isStayInLoop = false;
                for (int i = iDigit < Factor2.Length ? 0 : iDigit - Factor2.Length + 1; i < Factor1.Length && i <= iDigit; i++)
                {
                    iProduct = Product.abBytes[iDigit] + Factor1.abBytes[i] * Factor2.abBytes[iDigit - i];
                    if (iProduct > 9)
                    {
                        iQuotient = iProduct / 10;
                        iProduct -= 10 * iQuotient;
                        iCarry += iQuotient;
                    }
                    Product.abBytes[iDigit] = (byte)iProduct;
                    isStayInLoop = true;
                }
                iDigit++;
            } while (isStayInLoop);

            while (iCarry > 0)
            {
                iQuotient = iCarry / 10;
                Product.abBytes[iDigit] = (byte)(iCarry - 10 * iQuotient);
                iCarry = iQuotient;
                iDigit++;
            }
            Product.TrimLeadingZeros();
            return Product;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static DecimalInt operator /(DecimalInt Dividend, DecimalInt Divisor)
        {
            int iDecimal, iDivisorInRemainder, iQuotient;
            DecimalInt Quotient, Remainder, Ten;

            if ((Divisor.Length == 1) && (Divisor.abBytes[0] == 0))
                throw new DivideByZeroException("Division by zero.");
            else
            {
                Quotient = new DecimalInt(Dividend.Length);
                Remainder = new DecimalInt("0");
                Ten = new DecimalInt("10");

                for (int i = Dividend.Length - 1; i >= 0; i--)
                {
                    Remainder = Ten * Remainder + new DecimalInt(Dividend.abBytes[i]);
                    iDivisorInRemainder = 0;

                    if (Remainder >= Divisor)
                    {
                        do
                        {
                            iDivisorInRemainder++;
                            Remainder -= Divisor;

                        } while (Remainder >= Divisor);
                    }

                    iDecimal = i;
                    do
                    {
                        iQuotient = iDivisorInRemainder / 10;
                        Quotient.abBytes[iDecimal] += (byte)(iDivisorInRemainder - 10 * iQuotient);
                        iDivisorInRemainder = iQuotient;
                        if (Quotient.abBytes[iDecimal] > 9)
                        {
                            Quotient.abBytes[iDecimal] -= 10;
                            iDivisorInRemainder++;
                        }
                        iDecimal++;
                    } while (iDivisorInRemainder > 0);
                }
            }
            Quotient.TrimLeadingZeros();
            return Quotient;
        }
        #endregion

        #region properties

        /// <summary></summary>
        public byte[] abBytes
        {
            get { return _abBytes; }
        }

        /// <summary></summary>
        public bool isEven
        {
            get { return (_abBytes[0] & 0x01) == 0; }
            set
            {
                if (value)
                    _abBytes[0] &= 0xfe;
                else
                    _abBytes[0] |= 0x01;
            }
        }

        /// <summary></summary>
        public int Length
        {
            get { return _abBytes.Length; }
        }

        /// <summary></summary>
        public bool isOdd
        {
            get { return (_abBytes[0] & 0x01) == 1; }
            set
            {
                if (value)
                    _abBytes[0] |= 0x01;
                else
                    _abBytes[0] &= 0xfe;
            }
        }
        #endregion

        #region methods

        /// <summary></summary>
        private void DoubleThis()
        {
            byte[] abNewBytes;
            int i;

            if (_abBytes[_abBytes.Length - 1] > 4)
            {
                abNewBytes = new byte[_abBytes.Length + 1];
                for (i = 0; i < _abBytes.Length; i++)
                    abNewBytes[i] = _abBytes[i];
                abNewBytes[_abBytes.Length] = 0;
                _abBytes = abNewBytes;
            }

            for (i = _abBytes.Length - 1; i > 0; i--)
            {
                _abBytes[i] <<= 1;
                if (_abBytes[i - 1] > 4)
                {
                    _abBytes[i]++;
                    _abBytes[i - 1] -= 5;
                }
            }
            _abBytes[0] <<= 1;
        }


        /// <summary></summary>
        /// <param name=""></param>
        public bool Equals(DecimalInt Other)
        {
            bool isEqual = (Other != null) && (Length == Other.Length);

            if (isEqual)
            {
                for (int i = 0; i < Length; i++)
                    isEqual = isEqual && (_abBytes[i] == Other.abBytes[i]);
            }
            return isEqual;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public override bool Equals(object Other)
        {
            if (Other == null)
                return false;
            else
            {
                DecimalInt Integer = Other as DecimalInt;
                if (Integer == null)
                    return false;
                else
                    return Equals(Integer);
            }
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        private static int FirstByteDifference(DecimalInt First, DecimalInt Second)
        {
            int iReturn = 0;

            if (First.Length != Second.Length)
                throw new ArgumentException("Both numbers must be of equal length in function FirstByteDifference.");
            else
            {
                for (int i = First.Length - 1; i >= 0; i--)
                {
                    if (iReturn == 0)
                        iReturn = First.abBytes[i] - Second.abBytes[i];
                }
            }
            return iReturn;
        }

        /// <summary></summary>
        public override int GetHashCode()
        {
            return _abBytes.GetHashCode();
        }

        /// <summary></summary>
        public byte[] GetHexadecimal(int iLength)
        {
            byte bByte;
            byte[] abBytesCopy, abReturn;
            int i, j;

            abReturn = new byte[iLength];
            abBytesCopy = new byte[_abBytes.Length];
            for (i = 0; i < _abBytes.Length; i++)
                abBytesCopy[i] = _abBytes[i];

            for (i = iLength - 1; i >= 0; i--)
            {
                bByte = 0;
                for (j = 0; j < 8; j++)
                {
                    bByte >>= 1;
                    bByte = (byte)(bByte | (isOdd ? 0x80 : 0x00));
                    HalveThis();
                }
                abReturn[i] = bByte;
            }

            if ((_abBytes.Length > 1) || (_abBytes[0] > 0))   // make sure that the value is not greater than what we actually have read
                abReturn = null;

            _abBytes = abBytesCopy;
            return abReturn;
        }

        private void HalveThis()
        {
            int i;

            for (i = _abBytes.Length - 1; i > 0; i--)
            {
                if ((_abBytes[i] & 1) == 1)
                {
                    _abBytes[i - 1] += 10;
                    _abBytes[i]--;
                }
                _abBytes[i] >>= 1;
            }
            _abBytes[0] >>= 1;
            TrimLeadingZeros();
        }

        /// <summary></summary>
        public override string ToString()
        {
            StringBuilder DecimalIntStringBuilder = new StringBuilder();

            for (int i = Length - 1; i >= 0; i--)
                DecimalIntStringBuilder.Append((char)(_abBytes[i] + '0'));

            return DecimalIntStringBuilder.ToString();
        }

        /// <summary></summary>
        public void TrimLeadingZeros()
        {
            int i, iTrim = 0;
            byte[] _abNewValue;

            for (i = _abBytes.Length - 1; i > 0; i--)
            {
                if (_abBytes[i] == 0)
                    iTrim++;
                else
                    break;
            }

            if (iTrim > 0)
            {
                _abNewValue = new byte[_abBytes.Length - iTrim];
                for (i = 0; i < _abNewValue.Length; i++)
                    _abNewValue[i] = _abBytes[i];
                _abBytes = _abNewValue;
            }
        }
        #endregion
    }
}
