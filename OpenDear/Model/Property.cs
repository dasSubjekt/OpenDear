namespace OpenDear.Model
{
    using System;
    using System.Collections.Generic;


    /// <summary>A multi-purpose property for an entry in a combo box, a system setting or a data validation message.</summary>
    public class Property : DatabaseObject, IEquatable<Property>
    {
        private const int ciVariablesToStore = 3;

        private int _iNumber;
        string _sName, _sText;

        #region constructors

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        public Property(int iId, int iNumber, string sName, string sText) : base(-1)
        {
            _iIdInternal = iId;
            _iNumber = iNumber;
            _sName = sName;
            _sText = sText;
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        /// <param name=""></param>
        public Property(int iId, int iNumber, string sText) : this(iId, iNumber, string.Empty, sText)
        {
            _iIdInternal = iId;
            _iNumber = iNumber;
            _sText = sText;
        }

        /// <summary></summary>
        /// <param name=""></param>
        public Property(int iId, int iNumber) : this(iId, iNumber, string.Empty, string.Empty)
        {
        }

        /// <summary>Constructs a user message with a time stamp.</summary>
        /// <param name="CurrentTime">Time stamp</param>
        /// <param name="sText">Message to the user</param>
        public Property(DateTime CurrentTime, string sText) : this(-1, 0, string.Empty, sText)
        {
            _iIdInternal = 10000 * CurrentTime.Year + 100 * CurrentTime.Month + CurrentTime.Day;
            _iNumber = 10000000 * CurrentTime.Hour + 100000 * CurrentTime.Minute + 1000 * CurrentTime.Second + CurrentTime.Millisecond;
        }

        public Property(int iIdExternal, List<DatabaseVariable> ltVariables) : base(iIdExternal)
        {
            _iNumber = -1;
            _sName = _sText = string.Empty;
            SetDatabaseVariables(ltVariables);
        }
        #endregion

        #region operators

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator ==(Property First, Property Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return Equals(First, Second);
            else
                return First.Equals(Second);
        }

        /// <summary></summary>
        /// <param name=""></param>
        /// <param name=""></param>
        public static bool operator !=(Property First, Property Second)
        {
            if (((object)First) == null || ((object)Second) == null)
                return !Equals(First, Second);
            else
                return !(First.Equals(Second));
        }
        #endregion

        #region properties

        /// <summary></summary>
        public int iId
        {
            get { return _iIdInternal; }
        }

        /// <summary></summary>
        public string sId
        {
            get { return sIdInternal; }
        }

        /// <summary></summary>
        public int iNumber
        {
            get { return _iNumber; }
            set { _iNumber = value; }
        }

        /// <summary></summary>
        public string sNumber
        {
            get { return _iNumber.ToString(); }
        }

        /// <summary></summary>
        public string sName
        {
            get { return _sName; }
            set { _sName = value; }
        }

        /// <summary></summary>
        public string sText
        {
            get { return _sText; }
            set { _sText = value; }
        }

        /// <summary></summary>
        public string sTime
        {
            get
            {
                string sDigits = _iNumber.ToString("d9");
                return sDigits.Substring(0, 2) + ":" + sDigits.Substring(2, 2) + ":" + sDigits.Substring(4, 2) + "  " + sDigits.Substring(6, 3);
            }
        }
        #endregion

        #region methods

        /// <summary></summary>
        /// <param name=""></param>
        public bool Equals(Property Other)
        {
            return (Other != null) && (iId == Other.iId) && (sName == Other.sName);
        }

        /// <summary></summary>
        /// <param name=""></param>
        public override bool Equals(object Other)
        {
            if (Other == null)
            {
                return false;
            }
            else
            {
                if (Other is Property OtherProperty)
                    return Equals(OtherProperty);
                else
                    return false;
            }
        }

        public override int GetDatabaseVariables(List<DatabaseVariable> ltVariables)
        {
            int i, iReturn;

            i = iReturn = 0;
            foreach (DatabaseVariable Variable in ltVariables)
            {
                switch (i++)
                {
                    case 0: Variable.bId = 1; Variable.iValue = _iIdInternal; break;
                    case 1: Variable.bId = 2; Variable.iValue = _iNumber; break;
                    case 2: Variable.bId = 33; Variable.sValue = _sText; break;
                    // case 3: Variable.bId = 34; Variable.sValue = _sName; break;   the name needs not be stored
                }
                iReturn += (Variable.iLength + 1);
            }

            if ((i != ltVariables.Count) || (i != ciVariablesToStore))
                throw new FormatException("Failed to complete Property.GetDatabaseVariables().");
            else
                return iReturn;
        }

        /// <summary></summary>
        public override int GetHashCode()
        {
            return 3 * _iIdInternal.GetHashCode() + 5 * _sName.GetHashCode();
        }

        public override void SetDatabaseVariables(List<DatabaseVariable> ltVariables)
        {
            foreach (DatabaseVariable Variable in ltVariables)
            {
                switch (Variable.bId)
                {
                    case 1: _iIdInternal = Variable.iValue; break;
                    case 2: _iNumber = Variable.iValue; break;
                    case 33: _sText = Variable.sValue; break;
                    // case 34: _sName = Variable.sValue; break;   the name needs not be stored
                }
            }
        }

        /// <summary></summary>
        public override string ToString()
        {
            return _sText;
        }

        public override int VariablesToStore()
        {
            return ciVariablesToStore;
        }
        #endregion
    }
}
