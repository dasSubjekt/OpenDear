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
                sReturn = value.ToString();

                // switch (value)
                // {
                //     case PgpKeyFlags. : sReturn = "BitLocker"; break;
                //     case CryptoKey.nKeyFormat.KeePass: sReturn = "KeePass"; break;
                //     case CryptoKey.nKeyFormat.Password: sReturn = _ViewModelBase.Translate("KeyFormatPassword"); break;
                //     case CryptoKey.nKeyFormat.Private: sReturn = _ViewModelBase.Translate("KeyFormatPrivate"); break;
                //     case CryptoKey.nKeyFormat.Public: sReturn = _ViewModelBase.Translate("KeyFormatPublic"); break;
                // }
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
    }
}
