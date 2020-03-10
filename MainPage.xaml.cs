using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace AES
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private const int MIN_KEY_LENGTH = 44;
        private const int MIN_IV_LENGTH = 24;

        private string AESKey = "";
        private string AESIV = "";

        private IBuffer iBufferIV = null;
        private CryptographicKey cryptographicKey;

        public MainPage()
        {
            this.InitializeComponent();
        }

        public byte[] Encrypt(byte[] input)
        {
            IBuffer bufferMsg = CryptographicBuffer.ConvertStringToBinary(Encoding.ASCII.GetString(input), BinaryStringEncoding.Utf8);
            IBuffer bufferEncrypt = CryptographicEngine.Encrypt(cryptographicKey, bufferMsg, iBufferIV);
            
            return bufferEncrypt.ToArray();
        }

        public byte[] Decrypt(byte[] input)
        {
            IBuffer bufferDecrypt = CryptographicEngine.Decrypt(cryptographicKey, input.AsBuffer(), iBufferIV);
            
            return bufferDecrypt.ToArray();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            AESKey = text_box_encryption_key.Text;
            AESIV = text_box_encryption_iv.Text;

            IBuffer iBufferKey = Convert.FromBase64String(StringToKey(AESKey)).AsBuffer();
            iBufferIV = Convert.FromBase64String(StringToKey(AESIV)).AsBuffer();
            SymmetricKeyAlgorithmProvider provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            cryptographicKey = provider.CreateSymmetricKey(iBufferKey);

            byte[] b = Encoding.ASCII.GetBytes(text_box_text_to_encrypt.Text);
            txt.Text = Encoding.ASCII.GetString(Decrypt(Encrypt(b)));
        }

        private string StringToKey(string s)
        {
            if(s.Length < MIN_KEY_LENGTH)
            {
                double d = MIN_KEY_LENGTH / s.Length;
                int div = (int)Math.Ceiling(d);
                s = RepeatString(s, div);
            }
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(s));
        }

        private string StringToIV(string s)
        {
            if (s.Length < MIN_IV_LENGTH)
            {
                double d = MIN_IV_LENGTH / s.Length;
                int div = (int)Math.Ceiling(d);
                s = RepeatString(s, div);
            }
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(s));
        }

        private string RepeatString(string s, int n)
        {
            return new StringBuilder(s.Length * n).AppendJoin(s, new string[n + 1]).ToString();
        }
    }
}
