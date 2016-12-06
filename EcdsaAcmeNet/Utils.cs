using System;
using System.Linq;
using Org.BouncyCastle.Math;

namespace EcdsaAcmeNet
{
    public static class Utils
    {
        public const int KeySize = 256;

        public const string BaseUri = "https://acme-v01.api.letsencrypt.org/";
        public const string TestBaseUri = "https://acme-staging.api.letsencrypt.org/directory";

        public static sbyte[] ToJavaByteArray(this BigInteger bigInt)
        {
            return bigInt.ToByteArray().Reverse().Select(x => (sbyte)x).ToArray();
        }

        public static string Base64UrlEncode(byte[] raw)
        {
            // remove leading zeros
            raw = raw.SkipWhile(x => x == 0).ToArray();

            var str = Convert.ToBase64String(raw).TrimStart(new[] { '0' });
            var chArray = new char[1];
            const int index = 0;
            const int num = 61;
            chArray[index] = (char)num;
            return str.Split(chArray)[0].Replace('+', '-').Replace('/', '_').TrimEnd(new[] { '=' });
        }
    }
}
