namespace OpenDear.ViewModel
{
    using System;
    using System.Windows;
    using OpenDear.Crypto;
    using System.Windows.Data;
    using System.Globalization;


    /// <summary></summary>
    public class ValueTranslator : IValueConverter
    {
        private ViewModelBase _ViewModelBase;


        /// <summary></summary>
        public ValueTranslator()
        {
            _ViewModelBase = (ViewModelBase)Application.Current.MainWindow.DataContext;
        }

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string sReturn = string.Empty;

            if (targetType != typeof(string))
            {
                throw new ArgumentException("ValueTranslator can only convert into type string.");
            }
            else if (value is PgpSignature.nTranslatedKeyFlags)
            {
                PgpSignature.nTranslatedKeyFlags eFlags = (PgpSignature.nTranslatedKeyFlags)value;

                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.Certify, "Certify");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.VerifyCertificates, "VerifyCertificates");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.Sign, "Sign");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.VerifySignatures, "VerifySignatures");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.Decrypt, "Decrypt");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.Encrypt, "Encrypt");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.Authenticate, "Authenticate");
                sReturn = IfTrueAdd(sReturn, eFlags & PgpSignature.nTranslatedKeyFlags.VerifyAuthenticity, "VerifyAuthenticity");

                if (string.IsNullOrEmpty(sReturn))
                    sReturn = _ViewModelBase.Translate("None");

            }
            else if (value is PgpToken.nType)
            {
                switch (value)
                {
                    case PgpToken.nType.Private: sReturn = _ViewModelBase.Translate("Private"); break;
                    case PgpToken.nType.Public: sReturn = _ViewModelBase.Translate("Public"); break;
                    case PgpToken.nType.Symmetric: sReturn = _ViewModelBase.Translate("Symmetric"); break;
                    default: sReturn = _ViewModelBase.Translate("Error"); break;
                }
            }
            else
            {
                throw new ArgumentException("ValueTranslator cannot convert from type " + value.GetType().ToString() + ".");
            }
            return sReturn;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return Binding.DoNothing;
        }

        private string IfTrueAdd(string sResult, PgpSignature.nTranslatedKeyFlags eFlags, string sPhrase)
        {
            if ((eFlags != PgpSignature.nTranslatedKeyFlags.None) && !string.IsNullOrEmpty(sPhrase))
                sResult += (string.IsNullOrEmpty(sResult) ? string.Empty : ", ") + _ViewModelBase.Translate(sPhrase);

            return sResult;
        }
    }
}
