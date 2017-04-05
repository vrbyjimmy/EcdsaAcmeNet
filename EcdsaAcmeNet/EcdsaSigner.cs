using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using ACMESharp.JOSE;
using Org.BouncyCastle.Math;

namespace EcdsaAcmeNet
{
    public class EcdsaSigner : ISigner, IDisposable
    {
        private object jwk;
        private ECDsaCng cryptoProvider;

        public string JwsAlg
        {
            get { return "ES256"; }
        }

        public void Dispose()
        {
            if (this.cryptoProvider != null)
            {
                this.cryptoProvider.Dispose();
            }
            this.cryptoProvider = null;
        }

        public void Init()
        {
            this.cryptoProvider = new ECDsaCng(256);
        }

        public void Save(Stream stream)
        {
            using (var streamWriter = new StreamWriter(stream))
            {
                streamWriter.Write(this.cryptoProvider.ToXmlString(ECKeyXmlFormat.Rfc4050));
            }
        }

        public void Load(Stream stream)
        {
            using (var streamReader = new StreamReader(stream))
            {
                this.cryptoProvider.FromXmlString(streamReader.ReadToEnd(), ECKeyXmlFormat.Rfc4050);
            }
        }

        public object ExportJwk(bool canonical = false)
        {
            if (this.jwk == null)
            {
                var publicBlob = this.cryptoProvider.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                BigInteger x, y;
                UnpackEccPublicBlob(publicBlob, out x, out y);

                this.jwk = (object) new
                {
                    crv = "P-256",
                    kty = "EC",
                    x = Utils.Base64UrlEncode(x.ToByteArray().Reverse().ToArray()),
                    y = Utils.Base64UrlEncode(y.ToByteArray().Reverse().ToArray())
                };
            }
            return this.jwk;
        }

        internal static void UnpackEccPublicBlob(byte[] blob, out BigInteger x, out BigInteger y)
        {
            var count = BitConverter.ToInt32(blob, 4);
            x = new BigInteger(ReverseBytes(blob, 8, count, true));
            y = new BigInteger(ReverseBytes(blob, 8 + count, count, true));
        }

        private static byte[] ReverseBytes(byte[] buffer, int offset, int count, bool padWithZeroByte)
        {
            var numArray = !padWithZeroByte ? new byte[count] : new byte[count + 1];
            var num = offset + count - 1;
            for (var index = 0; index < count; ++index)
            {
                numArray[index] = buffer[num - index];
            }

            return numArray;
        }

        public byte[] Sign(byte[] raw)
        {
            return this.cryptoProvider.SignData(raw);
        }
    }
}
