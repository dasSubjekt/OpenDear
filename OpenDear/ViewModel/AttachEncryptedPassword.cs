namespace OpenDear.ViewModel
{
    using System;
    using System.Text;
    using System.Windows;
    using System.Windows.Controls;
    using System.Security.Cryptography;


    /// <summary>Helper class that attaches an RSA-encrypted one-way DependencyProperty to a PasswordBox.</summary>
    public static class AttachEncryptedPassword
    {
        public static readonly DependencyProperty AttachProperty =
            DependencyProperty.RegisterAttached("Attach",
            typeof(bool), typeof(AttachEncryptedPassword), new PropertyMetadata(false, Attach));

        public static readonly DependencyProperty EncryptedPasswordProperty =
            DependencyProperty.RegisterAttached("EncryptedPassword",
            typeof(byte[]), typeof(AttachEncryptedPassword));

        public static readonly DependencyProperty PasswordLengthProperty =
            DependencyProperty.RegisterAttached("PasswordLength",
            typeof(int), typeof(AttachEncryptedPassword), new PropertyMetadata(0, OnPasswordLengthChanged));

        public static readonly DependencyProperty PublicRsaEncryptorProperty =
            DependencyProperty.RegisterAttached("PublicRsaEncryptor",
            typeof(RSACng), typeof(AttachEncryptedPassword));

        public static bool GetAttach(DependencyObject DepObj)
        {
            return (bool)DepObj.GetValue(AttachProperty);
        }
        
        public static void SetAttach(DependencyObject DepObj, bool isValue)
        {
            DepObj.SetValue(AttachProperty, isValue);
        }
        
        public static byte[] GetEncryptedPassword(DependencyObject DepObj)
        {
            return (byte[])DepObj.GetValue(EncryptedPasswordProperty);
        }
        
        public static void SetEncryptedPassword(DependencyObject DepObj, byte[] abValue)
        {
            DepObj.SetValue(EncryptedPasswordProperty, abValue);
        }
        
        public static int GetPasswordLength(DependencyObject DepObj)
        {
            return (int)DepObj.GetValue(PasswordLengthProperty);
        }
        
        public static void SetPasswordLength(DependencyObject DepObj, int iValue)
        {
            DepObj.SetValue(PasswordLengthProperty, iValue);
        }
        
        public static RSACng GetPublicRsaEncryptor(DependencyObject DepObj)
        {
            return (RSACng)DepObj.GetValue(PublicRsaEncryptorProperty);
        }
        
        public static void SetPublicRsaEncryptor(DependencyObject DepObj, RSACng Value)
        {
            DepObj.SetValue(PublicRsaEncryptorProperty, Value);
        }

        private static void Attach(DependencyObject Sender, DependencyPropertyChangedEventArgs EventArguments)
        {
            if (Sender is PasswordBox PwdBox)
            {
                if ((bool)EventArguments.OldValue)
                {
                    PwdBox.PasswordChanged -= PasswordChanged;
                }

                if ((bool)EventArguments.NewValue)
                {
                    PwdBox.PasswordChanged += PasswordChanged;
                }
            }
        }

        private static void OnPasswordLengthChanged(DependencyObject Sender, DependencyPropertyChangedEventArgs EventArguments)
        {
            if ((Sender is PasswordBox PwdBox) && ((int)EventArguments.NewValue == 0))
            {
                PwdBox.Password = string.Empty;
            }
        }

        /// <summary>Writes the password to EncryptedPasswordProperty, in order not to have its clear text in memory.</summary>
        private static void PasswordChanged(object Sender, RoutedEventArgs EventArguments)
        {
            byte[] abPlain, abEncrypted;
            int iPasswordLength;
            PasswordBox PwdBox = Sender as PasswordBox;

            RSACng RsaEncryptor = (RSACng)PwdBox.GetValue(PublicRsaEncryptorProperty);
            if (RsaEncryptor != null)
            {
                abPlain = Encoding.UTF8.GetBytes(PwdBox.Password);   // we could be using SecurePassword.ToString() here to the same effect

                iPasswordLength = PwdBox.Password.Length;
                if (iPasswordLength == 0)
                    abEncrypted = null;
                else
                    abEncrypted = RsaEncryptor.Encrypt(abPlain, RSAEncryptionPadding.Pkcs1);

                PwdBox.SetValue(PasswordLengthProperty, iPasswordLength);
                PwdBox.SetValue(EncryptedPasswordProperty, abEncrypted);
            }
        }
    }
}