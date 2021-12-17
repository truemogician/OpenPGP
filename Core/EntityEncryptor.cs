using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using TrueMogician.Exceptions;

namespace Core {
	public static class EntityEncryptor {
		/// <summary>
		///     Encrypt <paramref name="srcPaths" /> and save the encrypted file to <paramref name="dstPath" />
		/// </summary>
		/// <param name="user">User credential used for encryption</param>
		/// <param name="srcPaths">Paths of entities to be encrypted</param>
		/// <param name="dstPath">Path where the encrypted file will be saved.</param>
		/// <returns>Path where the encrypted file is saved</returns>
		/// <exception cref="FileSystemEntityNotFoundException" />
		/// <exception cref="FileExistedException" />
		public static string EncryptEntities(this UserCredential user, string[] srcPaths, string? dstPath = null) {
			if (srcPaths.Length == 0)
				throw new ArgumentException(null, nameof(srcPaths));
			if (srcPaths.FirstOrDefault(path => !Directory.Exists(path) && !File.Exists(path)) is { } notFoundPath)
				throw new FileSystemEntityNotFoundException(path: notFoundPath);
			dstPath ??= (srcPaths.Length == 1 ? srcPaths[0] : Path.Combine(Path.GetDirectoryName(srcPaths[0])!, Path.GetFileName(Path.GetDirectoryName(srcPaths[0])!))) + ".pgp";
			if (File.Exists(dstPath))
				throw new FileExistedException(path: dstPath);
			string tmpFile;
			do {
				tmpFile = Path.GetRandomFileName();
			} while (File.Exists(tmpFile));
			using (var archive = ZipFile.Open(tmpFile, ZipArchiveMode.Create)) {
				foreach (var path in srcPaths)
					if (File.Exists(path))
						archive.CreateEntryFromFile(path);
					else
						archive.CreateEntryFromDirectory(path);
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

		/// <summary>
		///     Decrypt <paramref name="srcPath" /> to <paramref name="dstDirectory" />
		/// </summary>
		/// <param name="user">User credential used for decryption</param>
		/// <param name="srcPath">Path of the encrypted file</param>
		/// <param name="dstDirectory">Path where decrypted entities will be saved</param>
		/// <param name="conflictStrategy">Controls the action to take when decrypted entities conflict with existing files</param>
		/// <returns>Path of the directory where decrypted entities are saved</returns>
		/// <exception cref="FileNotFoundException" />
		/// <exception cref="FileExistedException" />
		/// <exception cref="AuthenticationException" />
		/// <exception cref="InvalidDataException" />
		public static string DecryptEntity(this UserCredential user, string srcPath, string? dstDirectory = null, ZipArchiveExtensions.ConflictStrategy conflictStrategy = ZipArchiveExtensions.ConflictStrategy.Throw) {
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
			ZipArchive archive;
			try {
				archive = ZipFile.OpenRead(tmpFile);
			}
			catch (InvalidDataException) {
				throw new InvalidDataException($"Encrypted file {srcPath} is corrupted");
			}
			archive.ExtractToDirectory(dstDirectory, conflictStrategy);
			archive.Dispose();
			File.Delete(tmpFile);
			return dstDirectory;
		}
	}
}