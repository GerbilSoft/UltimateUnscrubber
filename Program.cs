using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UltimateUnscrubber
{
    class Program
    {
        static FileStream source;
        static FileStream dest;
        static bool scrubbed;
        static bool decrypted;
        static bool original;
        static byte[] buffer = new byte[0x8000 * 8 * 8];
        static SHA1 hasher = SHA1.Create();
        static Aes aes = Aes.Create();
        static byte[] IV = new byte[16];
        static bool do_decrypt;

        enum PartitionType { DATA, UPDATE, CHANNEL };
        enum TransformType { Encrypt, Decrypt };

        static Program()
        {
            aes.Padding = PaddingMode.None;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Wii Ultimate Unscrubber v0.3.2\n");
            if (args.Length < 1)
            {
                Console.WriteLine("Drop the ISO on this exe\n\nOr use:");
                Console.WriteLine("UnltimateUnscrubber [decrypt] <game.iso>");
                Console.ReadKey();
                return;
            }
            var source_path = args.Length == 1 ? args[0]: args[1];
            Console.WriteLine(source_path+"\n");
            if (!File.Exists(source_path))
            {
                Console.WriteLine(source_path + " does not exist");
                Console.ReadKey();
                return;
            }
            source = File.OpenRead(source_path);
            var header = new byte[0x50000];
            if(source.Length >= 0x50000) Read(header.Length);
            if (source.Length < 0x50000 || ReadBigEndian(0x18) != 0x5D1C9EA3)
            {
                Console.WriteLine("Not a Wii ISO");
                Console.ReadKey();
                return;
            }
            Array.Copy(buffer, 0, header, 0, header.Length);
            var partitions_count = (int)ReadBigEndian(0x40000);
            var table_offset = (int)ReadBigEndian(0x40004) * 4;
            source.Position = (long)ReadBigEndian(table_offset) * 4 + 0x20000;
            Read(0x8000);
            decrypted = BinaryIsUniform(buffer, 0x26C, 20, 0);
            source.Position = source.Length - 16;
            Read(16);
            scrubbed = BinaryIsUniform(buffer, 0, 16, buffer[0]);
            original = !scrubbed && !decrypted;
            if (args.Length > 2)
            {
                Syntaxerror();
                return;
            }
            if (args.Length == 2) switch (args[0])
                {
                    case "decrypt":
                        do_decrypt = true;
                        break;
                    default:
                        Syntaxerror();
                        return;
                }
            
            if (!scrubbed && !do_decrypt) Console.WriteLine("The ISO doesn't seem to be scrubbed.\nTrying to unscrub anyway...\n");
            var new_file_path = source_path + ".new";
            dest = File.Create(new_file_path);
            CopyUpTo(header.Length);
            var disc_id = Encoding.ASCII.GetString(header, 0, 4);
            var disc_number = (int)header[6];
            var junk = new JunkStream(disc_id, disc_number, false, source.Length);
            var previous_data_end = (long)0x50000;
            for (var partition_table_index = 0; partition_table_index < 4; partition_table_index++)
            {
                header.CopyTo(buffer, 0);
                partitions_count = (int)ReadBigEndian(0x40000 + partition_table_index * 8);
                if (partitions_count == 0) continue;
                table_offset = (int)ReadBigEndian(0x40000 + partition_table_index * 8 + 4) * 4;
                for (var partition_index = 0; partition_index < partitions_count; partition_index++)
                {
                    header.CopyTo(buffer, 0);
                    var partition_offset = (long)ReadBigEndian(table_offset + partition_index * 8) * 4;
                    var partition_type = (PartitionType)ReadBigEndian(table_offset + partition_index * 8 + 4);
                    if (partition_table_index == 0 && partition_index == 0 && partition_type != PartitionType.UPDATE)
                        Console.WriteLine("!!! UPDATE partition is missing. Unscrub will probably fail. !!!\nTrying to unscrub anyway...\n");
                    FillSpace(previous_data_end, partition_offset, junk);
                    Console.WriteLine((do_decrypt ? "decrypting " : "restoring ") + (PartitionType)partition_type + " partition");
                    SetPosition(partition_offset);
                    TransformPartition();
                    previous_data_end = source.Position;
                }
            }
            Console.WriteLine("writing last data...");
            FillSpace(previous_data_end, source.Length, junk);
            source.Close();
            dest.Close();
            Console.WriteLine("renaming");
            Console.WriteLine(Path.GetFileName(source_path) + " -> " + Path.GetFileName(source_path + ".old"));
            if (File.Exists(source_path + ".old")) File.Delete(source_path + ".old");
            File.Move(source_path, source_path + ".old");
            Console.WriteLine(Path.GetFileName(new_file_path) + " -> " + Path.GetFileName(source_path));
            File.Move(new_file_path, source_path);
            Console.WriteLine("FINISHED ");
            Console.ReadKey();
        }
        static void FillSpace(long previous_data_end, long current_offset, JunkStream junk)
        {
            source.Position = previous_data_end;
            Read(32);
            if (do_decrypt || current_offset == 0xf800000 && !BinaryIsUniform(buffer, 0, 32, buffer[0]))
            {
                SetPosition(previous_data_end);
                CopyUpTo(current_offset);
            }
            else if (current_offset != 0xf800000 && current_offset > previous_data_end + 28)
            {
                SetPosition(previous_data_end + 28);
                junk.Position = source.Position;
                while (source.Position < current_offset)
                {
                    var to_write = buffer.Length;
                    to_write = (int)Math.Min(to_write, current_offset - source.Position);
                    junk.Read(buffer, 0, to_write);
                    source.Position += to_write;
                    Write();
                }
            }
            else SetPosition(current_offset);
        }
        static void Syntaxerror()
        {
            Console.WriteLine("Syntax error\n\nUsage\n");
            Console.WriteLine("UnltimateUnscrubber [decrypt] <game.iso>");
            Console.ReadKey();
        }
        static void TransformPartition()
        {
            Read(0x20000);
            Write();
            var partition_key = new byte[16];
            Array.Copy(buffer, 0x1bf, partition_key, 0, 16);
            var korean = buffer[0x1f1] == 1;
            aes.Key = korean ? ParseHex("63b82bb4f4614e2e13f2fefbba4c9b7e") : ParseHex("ebe42a225e8593e448d9c5457381aaf7");
            Array.Clear(IV, 0, 16);
            Array.Copy(buffer, 0x1dc, IV, 0, 8);
            aes.IV = IV;
            using(var cryptor = aes.CreateDecryptor()) cryptor.TransformBlock(partition_key, 0, 16, partition_key, 0);
            aes.Key = partition_key;
            var size = (long)ReadBigEndian(0x2bc) * 4;
            Read(0x8000);
            source.Position -= 0x8000;
            if (!decrypted) TransformBlock(0, TransformType.Decrypt);
            var partition_id = Encoding.ASCII.GetString(buffer, 0x400, 4);
            var disc = (int)buffer[0x406];
            var data_offset = source.Position;
            var junk = new JunkStream(partition_id, disc, true, size);
            var last_progress = 0;
            while (source.Position < data_offset + size)
            {
                Array.Clear(buffer, 0, buffer.Length);
                var to_read = 0x8000 * 8 * 8;
                to_read = (int)Math.Min(to_read, data_offset + size - source.Position);
                Read(to_read);
                for (var block_index = 0; block_index < to_read / 0x8000; block_index++)
                {
                    if (!decrypted) TransformBlock(block_index, TransformType.Decrypt);
                    if (!IsData(block_index))
                    {
                        junk.Position = dest.Position - data_offset + block_index * 0x8000;
                        junk.Read(buffer, block_index * 0x8000, 0x8000);
                    }
                }
                for (var block_index = 0; block_index < 64; block_index++)
                {
                    for (int i = 0; i < 31; i++) hasher.ComputeHash(buffer, block_index * 0x8000 + (i + 1) * 0x400, 0x400).CopyTo(buffer, block_index * 0x8000 + i * 20);
                    var subgroup_index = block_index / 8;
                    var block_in_subgroup_index = block_index % 8;
                    var h1 = hasher.ComputeHash(buffer, block_index * 0x8000, 31 * 20);
                    for (int block_in_subgroup_index2 = 0; block_in_subgroup_index2 < 8; block_in_subgroup_index2++)
                    {
                        var block_index2 = subgroup_index * 8 + block_in_subgroup_index2;
                        h1.CopyTo(buffer, block_index2 * 0x8000 + 0x280 + block_in_subgroup_index * 20);
                    }
                    if (block_in_subgroup_index == 7)
                    {
                        var h2 = hasher.ComputeHash(buffer, block_index * 0x8000 + 0x280, 8 * 20);
                        for (int block_index2 = 0; block_index2 < 64; block_index2++)
                            h2.CopyTo(buffer, block_index2 * 0x8000 + 0x340 + subgroup_index * 20);
                    }
                }
                if (!do_decrypt) for (var block_index = 0; block_index < 64; block_index++) TransformBlock(block_index, TransformType.Encrypt);
                Write();
                var progress = (int)(100 - (data_offset + size - source.Position) / (float)size * 100);
                if (progress >= last_progress + 5)
                {
                    Console.WriteLine(progress.ToString() + "%");
                    last_progress = progress;
                }
            }
        }

        static bool IsData(int block_index)
        {
            for (int i = 0; i < 31; i++)
                if (!BinariesAreEqual(hasher.ComputeHash(buffer, block_index * 0x8000 + (i + 1) * 0x400, 0x400), 0, buffer, block_index * 0x8000 + i * 20, 20)) 
                    return false;
            return true;
        }
        static void SetPosition(long position)
        {
            source.Position = position;
            dest.Position = position;
        }
        static void TransformBlock(int block_index, TransformType transform_type)
        {
            Array.Clear(IV, 0, 16);
            aes.IV = IV;
            if (transform_type == TransformType.Decrypt) Array.Copy(buffer, block_index * 0x8000 + 0x3d0, IV, 0, 16);
            using (var cryptor = transform_type == TransformType.Decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor())
                cryptor.TransformBlock(buffer, block_index * 0x8000, 0x400, buffer, block_index * 0x8000);
            if (transform_type == TransformType.Encrypt) Array.Copy(buffer, block_index * 0x8000 + 0x3d0, IV, 0, 16);
            aes.IV = IV;
            using (var cryptor = transform_type == TransformType.Decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor())
                cryptor.TransformBlock(buffer, block_index * 0x8000 + 0x400, 0x7c00, buffer, block_index * 0x8000 + 0x400);
        }
        static void CopyUpTo(long position)
        {
            source.Position = dest.Position;
            while (position - source.Position > 0)
            {
                var to_read = buffer.Length;
                to_read = (int)Math.Min(to_read, position - source.Position);
                Read(to_read);
                Write();
            }
        }
        static void Read(int amount)
        {
            if (source.Read(buffer, 0, amount) != amount) throw new Exception();
        }
        static void Write()
        {
            dest.Write(buffer, 0, (int)(source.Position - dest.Position));
        }
        static bool BinariesAreEqual(byte[] d1, int offset1, byte[] d2, int offset2, int size)
        {
            for (int i = 0; i < size; i++) if (d1[i + offset1] != d2[i + offset2]) return false;
            return true;
        }
        static bool BinaryIsUniform(byte[] data, int offset, int size, byte value)
        {
            for (int i = 0; i < size; i++) if (data[i + offset] != value) return false;
            return true;
        }
        static uint ReadBigEndian(int offset)
        {
            Array.Reverse(buffer, offset, 4);
            var num = BitConverter.ToUInt32(buffer, offset);
            Array.Reverse(buffer, offset, 4);
            return num;
        }
        static byte[] ParseHex(string hex)
        {
            hex = hex.Replace(" ", "");
            if (hex.Length % 2 != 0) throw new Exception();
            var buf = new byte[hex.Length / 2];
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = byte.Parse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return buf;
        }
    }
}
