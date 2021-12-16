using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using TrueMogician.Exceptions;

namespace Core {
	public static class EntityEncryptor {
		/// <exception cref="FileSystemEntityNotFoundException" />
		/// <exception cref="FileExistedException" />
		public static string EncryptEntity(this UserCredential user, string srcPath, string? dstPath = null) {
			bool isDirectory = Directory.Exists(srcPath);
			if (!isDirectory && !File.Exists(srcPath))
				throw new FileSystemEntityNotFoundException(path: srcPath);
			dstPath ??= srcPath + ".pgp";
			if (File.Exists(dstPath))
				throw new FileExistedException(path: dstPath);
			string tmpFile;
			do {
				tmpFile = Path.GetRandomFileName();
			} while (File.Exists(tmpFile));
			if (isDirectory)
				ZipFile.CreateFromDirectory(srcPath, tmpFile, CompressionLevel.Fastest, true);
			else {
				using var zip = ZipFile.Open(tmpFile, ZipArchiveMode.Create);
				zip.CreateEntryFromFile(srcPath, Path.GetFileName(srcPath));
			}
			var randomAes = Aes.Create();
			using (var writer = new FileStream(dstPath, FileMode.Create, FileAccess.Write)) {
				writer.Write(UserCredentialEncryptor.Hasher.ComputeHash(user.Username.ToRawBytes()));
				byte[] encryptedKey = user.RSA.Encrypt(randomAes.Key, RSAEncryptionPadding.Pkcs1);
				byte[] encryptedIV = user.RSA.Encrypt(randomAes.IV, RSAEncryptionPadding.Pkcs1);
				writer.Write(BitConverter.GetBytes(encryptedKey.Length));
				writer.Write(BitConverter.GetBytes(encryptedIV.Length));
				writer.Write(encryptedKey);
				writer.Write(encryptedIV);
				writer.Write(randomAes.Encrypt(File.ReadAllBytes(tmpFile)));
			}
			File.Delete(tmpFile);
			return dstPath;
		}

		/// <exception cref="FileNotFoundException" />
		/// <exception cref="AuthenticationException" />
		public static string DecryptEntity(this UserCredential user, string srcPath, string? dstDirectory = null) {
			if (!File.Exists(srcPath))
				throw new FileNotFoundException($"File {srcPath} not found");
			dstDirectory ??= Path.GetDirectoryName(srcPath)!;
			if (!Directory.Exists(dstDirectory))
				Directory.CreateDirectory(dstDirectory);
			using var reader = new FileStream(srcPath, FileMode.Open, FileAccess.Read);
			var hashedUsername = reader.Read(32);
			if (!hashedUsername.SequenceEqual(UserCredentialEncryptor.Hasher.ComputeHash(user.Username.ToRawBytes())))
				throw new AuthenticationException($"Encrypted file {srcPath} doesn't belongs to user {user.Username}");
			var aes = Aes.Create();
			var keyLength = BitConverter.ToInt32(reader.Read(4));
			var ivLength = BitConverter.ToInt32(reader.Read(4));
			aes.Key = user.RSA.Decrypt(reader.Read(keyLength), RSAEncryptionPadding.Pkcs1);
			aes.IV = user.RSA.Decrypt(reader.Read(ivLength), RSAEncryptionPadding.Pkcs1);
			string tmpFile;
			do {
				tmpFile = Path.GetRandomFileName();
			} while (File.Exists(tmpFile));
			File.WriteAllBytes(tmpFile, aes.Decrypt(reader.ReadBytes()));
			ZipFile.ExtractToDirectory(tmpFile, dstDirectory);
			File.Delete(tmpFile);
			return dstDirectory;
		}
	}
}