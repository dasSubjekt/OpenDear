namespace OpenDear.Model
{
    using System;
    using System.Collections.Generic;


    public class DatabaseObject
    {
        protected int _iIdExternal, _iIdInternal;


        #region constructors

        protected DatabaseObject(int iIdExternal)
        {
            _iIdExternal = iIdExternal;
            _iIdInternal = -1;
        }

        #endregion

        #region properties

        /// <summary></summary>
        public int iIdExternal
        {
            get { return _iIdExternal; }
            set { _iIdExternal = value; }
        }

        /// <summary></summary>
        public string sIdExternal
        {
            get { return _iIdExternal.ToString(); }
        }

        /// <summary></summary>
        public int iIdInternal
        {
            get { return _iIdInternal; }
            set { _iIdInternal = value; }
        }

        /// <summary></summary>
        public string sIdInternal
        {
            get { return _iIdInternal.ToString(); }
        }

        #endregion

        #region methods

        public virtual int GetDatabaseVariables(List<DatabaseVariable> ltVariables)
        {
            return 0;
        }

        public virtual void SetDatabaseVariables(List<DatabaseVariable> ltVariables)
        {

        }

        public virtual int VariablesToStore()
        {
            return 0;
        }

        #endregion
    }
}
