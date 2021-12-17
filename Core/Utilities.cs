using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TrueMogician.Exceptions;

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

	public static class ZipArchiveExtensions {
		/// <inheritdoc cref="ZipFileExtensions.CreateEntryFromFile(ZipArchive, string, string)" />
		public static ZipArchiveEntry CreateEntryFromFile(this ZipArchive archive, string sourceFileName) => archive.CreateEntryFromFile(sourceFileName, Path.GetFileName(sourceFileName));

		/// <summary>
		///     Archives a directory and its content by compressing it and adding it to <paramref name="archive" />
		/// </summary>
		/// <inheritdoc cref="ZipFileExtensions.CreateEntryFromFile(ZipArchive, string, string, CompressionLevel)" />
		public static ZipArchiveEntry[] CreateEntryFromDirectory(this ZipArchive archive, string sourceDirectoryName, string? entryName = null, CompressionLevel compressionLevel = new()) {
			entryName ??= Path.GetFileName(sourceDirectoryName);
			if (!entryName.EndsWith("/"))
				entryName += "/";
			var result = new List<ZipArchiveEntry>();
			var files = Directory.GetFiles(sourceDirectoryName);
			var directories = Directory.GetDirectories(sourceDirectoryName);
			if (files.Length + directories.Length == 0)
				result.Add(archive.CreateEntry(entryName));
			result.AddRange(files.Select(file => archive.CreateEntryFromFile(file, Path.Combine(entryName, Path.GetFileName(file)))));
			foreach (var directory in Directory.GetDirectories(sourceDirectoryName))
				result.AddRange(archive.CreateEntryFromDirectory(directory, Path.Combine(entryName, Path.GetFileName(directory))));
			return result.ToArray();
		}

		/// <param name="conflictStrategy">Controls the action to take when decrypted entities conflict with existing files</param>
		/// <inheritdoc cref="ZipFileExtensions.ExtractToDirectory(ZipArchive, string)" />
		/// <exception cref="FileExistedException" />
		public static void ExtractToDirectory(this ZipArchive archive, string destinationDirectoryName, ConflictStrategy conflictStrategy) {
			var conflictFile = archive.Entries.FirstOrDefault(e => File.Exists(Path.Combine(destinationDirectoryName, e.FullName)));
			bool hasConflict = conflictFile is not null;
			if (hasConflict)
				switch (conflictStrategy) {
					case ConflictStrategy.Abort: return;
					case ConflictStrategy.Throw: throw new FileExistedException(path: conflictFile!.FullName);
				}
			else {
				archive.ExtractToDirectory(destinationDirectoryName);
				return;
			}
			foreach (var entry in archive.Entries) {
				var path = Path.Combine(destinationDirectoryName, entry.FullName);
				if (Path.GetDirectoryName(path) is { } dir && !Directory.Exists(dir))
					Directory.CreateDirectory(dir);
				else if (hasConflict && File.Exists(path))
					switch (conflictStrategy) {
						case ConflictStrategy.Skip: continue;
						case ConflictStrategy.Rename:
							path = GetNonConflictingName(path);
							break;
					}
				if (entry.Name == string.Empty)
					continue;
				entry.ExtractToFile(path, conflictStrategy == ConflictStrategy.Overwrite);
			}
		}

		private static string GetNonConflictingName(string path) {
			if (!File.Exists(path))
				return path;
			string folder = Path.GetDirectoryName(path)!;
			string name = Path.GetFileNameWithoutExtension(path);
			string ext = Path.GetExtension(path);
			for (var i = 1;; ++i) {
				path = Path.Combine(folder, $"{name}({i}){ext}");
				if (!File.Exists(path))
					return path;
			}
		}

		public enum ConflictStrategy : byte {
			/// <summary>
			///     Throw an <see cref="FileExistedException" />
			/// </summary>
			Throw,

			/// <summary>
			///     Abort the entire operation
			/// </summary>
			Abort,

			/// <summary>
			///     Skip all conflicting entities
			/// </summary>
			Skip,

			/// <summary>
			///     Overwrite existing entities
			/// </summary>
			Overwrite,

			/// <summary>
			///     Rename the coming entities
			/// </summary>
			Rename
		}
	}

	public static class MiscellaneousExtensions {
		private static readonly Encoding Encoding = Encoding.GetEncoding("iso-8859-1");

		/// <summary>
		///     Convert to string using 8-bit no-loss encoding ISO-8859-1
		/// </summary>
		public static string ToRawString(this byte[] bytes) => Encoding.GetString(bytes);

		/// <summary>
		///     Convert to bytes using no-loss 8-bit encoding ISO-8859-1
		/// </summary>
		public static byte[] ToRawBytes(this string str) => Encoding.GetBytes(str);

		/// <summary>
		///     Read all bytes from <paramref name="stream" />
		/// </summary>
		public static byte[] ReadBytes(this Stream stream) {
			using var memoryStream = new MemoryStream();
			stream.CopyTo(memoryStream);
			return memoryStream.ToArray();
		}

		/// <summary>
		///     Read <paramref name="count" /> bytes from <paramref name="stream" />
		/// </summary>
		public static byte[] Read(this Stream stream, int count) {
			var buffer = new byte[count];
			int actual = stream.Read(buffer, 0, count);
			return actual == count ? buffer : buffer[..actual];
		}
	}
}