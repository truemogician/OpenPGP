using System.Numerics;
using System.Security.Cryptography;

namespace Core {
	public static class RSAParametersCalculator {
		public static RSAParameters Calculate(byte[] p, byte[] q, byte[] e) {
			var pp = new BigInteger(p);
			var qq = new BigInteger(q);
			var ee = new BigInteger(e);
			var dd = ee.GetInverse((pp - 1) * (qq - 1));
			return new RSAParameters {
				P = p,
				Q = q,
				Exponent = e,
				Modulus = (pp * qq).ToByteArray(),
				D = dd.ToByteArray(),
				InverseQ = qq.GetInverse(pp).ToByteArray(),
				DP = (dd % (pp - 1)).ToByteArray(),
				DQ = (dd % (qq - 1)).ToByteArray()
			};
		}

		public static BigInteger GetInverse(this BigInteger a, BigInteger p) {
			BigInteger i = p, v = 0, d = 1;
			while (a > 0) {
				BigInteger t = i / a, x = a;
				a = i % x;
				i = x;
				x = d;
				d = v - t * x;
				v = x;
			}
			v %= p;
			return v < 0 ? (v + p) % p : v;
		}
	}
}