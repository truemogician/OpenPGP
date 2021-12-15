using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Core {
	public static class AesExtensions {
		public static byte[] Encrypt(this ICryptoTransform encryptor, byte[] plainText) {
			using var ms = new MemoryStream();
			using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
				cs.Write(plainText, 0, plainText.Length);
			return ms.ToArray();
		}

		public static string Encrypt(this ICryptoTransform encryptor, string plainText) => encryptor.Encrypt(plainText.ToRawBytes()).ToRawString();

		public static byte[] Encrypt(this Aes aes, byte[] plainText) => aes.CreateEncryptor().Encrypt(plainText);

		public static string Encrypt(this Aes aes, string plainText) => aes.CreateEncryptor().Encrypt(plainText);

		public static byte[] Decrypt(this ICryptoTransform decryptor, byte[] cipherText) {
			using var ms = new MemoryStream(cipherText);
			using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
			using var result = new MemoryStream();
			cs.CopyTo(result);
			return result.ToArray();
		}

		public static string Decrypt(this ICryptoTransform decryptor, string cipherText) => decryptor.Decrypt(cipherText.ToRawBytes()).ToRawString();

		public static byte[] Decrypt(this Aes aes, byte[] cipherText) => aes.CreateDecryptor().Decrypt(cipherText);

		public static string Decrypt(this Aes aes, string cipherText) => aes.CreateDecryptor().Decrypt(cipherText);
	}

	public static class MiscellaneousExtensions {
		private static readonly Encoding Encoding = Encoding.GetEncoding("iso-8859-1");

		public static string ToRawString(this byte[] bytes) => Encoding.GetString(bytes);

		public static byte[] ToRawBytes(this string str) => Encoding.GetBytes(str);

		public static byte[] ReadBytes(this Stream stream) {
			using var memoryStream = new MemoryStream();
			stream.CopyTo(memoryStream);
			return memoryStream.ToArray();
		}

		public static byte[] Read(this Stream stream, int count) {
			var buffer = new byte[count];
			int actual = stream.Read(buffer, 0, count);
			return actual == count ? buffer : buffer[..actual];
		}
	}
}