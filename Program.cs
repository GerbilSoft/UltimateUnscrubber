using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;

namespace UltimateUnscrubber
{
    class Program
    {
        enum JobType { Unscrub, Decrypt, ExtractUpdate };
        enum PartitionType { DATA, UPDATE, CHANNEL };

        class RedumpRecord
        {
            public uint crc;
            public byte[] sha1;
        }

        static void Main(string[] args)
        {
            var additional_dir = "UltimateUnscrubber_files";
            Environment.CurrentDirectory = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
            if (!Directory.Exists(additional_dir)) Directory.CreateDirectory(additional_dir);
            Environment.CurrentDirectory = Path.Combine(Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]), additional_dir);
            if (!Directory.Exists("update_partitions")) Directory.CreateDirectory("update_partitions");
            Console.WriteLine("Wii Ultimate Unscrubber v0.4 beta\n");
            ConvertPartitionFiles(Directory.GetFiles("update_partitions", "*", SearchOption.AllDirectories));
            string iso_path;
            JobType job;
            switch (args.Length)
            {
                case 1:
                    job = JobType.Unscrub;
                    iso_path = args[0];
                    break;
                case 2:
                    switch (args[0])
                    {
                        case "decrypt":
                            job = JobType.Decrypt;
                            break;
                        default:
                            PrintSyntax();
                            return;
                    } 
                    iso_path = args[1];
                    break;
                default: 
                    PrintSyntax();
                    return;
            }

            Console.WriteLine(iso_path);
            string[] iso_files;
            if (File.Exists(iso_path)) iso_files = new string[] { iso_path };
            else if (Directory.Exists(iso_path))
            {
                iso_files = Directory.GetFiles(iso_path, "*", SearchOption.AllDirectories);
                job = JobType.ExtractUpdate;
            }
            else
            {
                Console.WriteLine("\nFile or directory do not exist");
                Console.ReadKey();
                return;
            }

            if (job == JobType.ExtractUpdate)
            {
                Console.WriteLine("Extracting UPDATE partitions");
                var progress = new Progress(iso_files.Length, 5);
                for (var i = 0; i < iso_files.Length; i++)
                {
                    var source_path = iso_files[i];
                    Console.WriteLine(source_path);
                    var dest_folder = @"update_partitions";
                    try
                    {
                        using (var source = OpenFile(source_path))
                        {
                            if (source == null) continue;
                            var partition_offset = source.ReadBE32(0x40020) * 4;
                            if (partition_offset != 0x50000 || source.ReadBE32(0x40024) != 1) continue;
                            var source_partition = new Partition(source, 0x50000);
                            var name = BitConverter.ToString(source_partition.content_sha1).Replace("-", "") + "_" + (source_partition.korean ? "K" : "N");
                            if (Directory.GetFiles(dest_folder, "*" + name + "*", SearchOption.TopDirectoryOnly)
                                .Where(x => Regex.IsMatch(x, name + @"_\w{8}")).Count() > 0) continue;
                            name = Path.Combine(dest_folder, name);
                            var target_crc = new CRC();
                            using (var dest = new CryptoStream(File.Create("temp"), target_crc, CryptoStreamMode.Write))
                            {
                                var dp = new Partition(dest, source_partition.Header, true);
                                source_partition.Copy(dp, source_partition.Length, 0);
                            }
                            long space_size = 0xf800000 - source_partition.PartitionLength - 0x50000;
                            var crc1 = target_crc.Value;
                            target_crc = new CRC();
                            using (var t = new CryptoStream(new VoidStream(), target_crc, CryptoStreamMode.Write)) VoidStream.Stream.Copy(t, space_size, 0);
                            crc1 = ~CRC.Combine(~crc1, ~target_crc.Value, space_size);
                            File.Move("temp", name + "_" + crc1.ToString("X8"));
                        }
                    }
                    catch (Partition.H3Error)
                    {
                        Console.WriteLine("H3 checksum error. Either the file is corrupt or this is a bug. Please report this error");
                    }
                    progress.Print(iso_files.Length - i);
                }
            }
            else
            {
                var redump = new List<RedumpRecord>();
                foreach (var dat_file in Directory.GetFiles(@".", "*.dat", SearchOption.TopDirectoryOnly))
                {
                    Console.WriteLine("\nUsing checksums from file " + Path.GetFileName(dat_file));
                    var count = 0;
                    foreach (var line in File.ReadAllLines(dat_file))
                    {
                        var m = Regex.Match(line, @"crc\s*=\s*""(\w{8})"".*sha1\s*=\s*""(\w{40})""");
                        if (!m.Success) continue;
                        var crc = uint.Parse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber);
                        var sha1 = BigNumber.ParseHex(m.Groups[2].Value);
                        if (!redump.Any(x => x.sha1.Equals(0, sha1, 0, 20)))
                        {
                            redump.Add(new RedumpRecord() { crc = crc, sha1 = sha1 });
                            count++;
                        }
                    }
                    Console.WriteLine("Found " + count + " new checksums");
                }

                //if (iso_files.Length > 1) return;
                //var update_partitions = new List<UpdatePartitionRecord>();
                //progress = new Progress(update_files.Length, 5);
                //Console.WriteLine("Preparing UPDATE partitions");
                //foreach (var line in File.ReadAllLines("extended_crc.txt"))
                //{
                //    var m = Regex.Match(line, @"(\w+)\s(\w{8})");
                //    if (!m.Success) continue;
                //    var file = m.Groups[1].Value;
                //    var crc = uint.Parse(m.Groups[2].Value, System.Globalization.NumberStyles.HexNumber);
                //    update_partitions.Add(new UpdatePartitionRecord() {  path = file, crc = crc });
                //}
                //for(var i=0;i< update_files.Length;i++)
                //{
                //    var file = update_files[i];
                //    if (update_partitions.Any(x => x.path == file)) continue;
                //    var target_crc = new CRC();
                //    var space_size = 0xf800000 - File2.GetFileSize(file) - 0x50000;
                //    using (var t = new CryptoStream(new VoidStream(), target_crc, CryptoStreamMode.Write)) VoidStream.Stream.Copy(t, space_size, 0);
                //    var old_crc = uint.Parse(file.Substring(file.Length - 8,8),  System.Globalization.NumberStyles.HexNumber);
                //    update_partitions.Add(new UpdatePartitionRecord() { path = file, crc = ~CRC.Combine(~old_crc, ~target_crc.Value, space_size) });
                //    progress.Print(update_files.Length - i);
                //}
                //File.WriteAllLines("extended_crc.txt", update_partitions.Select(x => x.path + " " + x.crc.ToString("X8")).ToArray());

                var progress = new Progress(iso_files.Length, 5);
                for (var file_index = 0; file_index < iso_files.Length; file_index++)
                {
                    var source_file_path = iso_files[file_index];
                    var has_update_partition = true;
                    Console.WriteLine(job.ToString() + " " + source_file_path);
                    var found = false;
                    try
                    {
                        var new_target = Path.GetDirectoryName(source_file_path) + "/" + Path.GetFileNameWithoutExtension(source_file_path) + ".iso";
                        var target_path = new_target + ".new";
                        using (var source = OpenFile(iso_path))
                        {
                            //using (var f = File.Create(target_path)) source.Copy(0, f, source.Length, 5);
                            has_update_partition = source.ReadBE32(0x40024) == 1;
                            var original_header = source.Read(0, 0x50000);
                            var update_partitions = (IEnumerable<string>)Directory.GetFiles("update_partitions", "*");
                            if (source.ReadBE32(0x40024) == 1) update_partitions = new[] { source_file_path }.Union(update_partitions);
                            else
                            {
                                Console.WriteLine("The ISO does not contain an UPDATE partition");
                                if (redump.Count == 0 || update_partitions.Count() == 0)
                                {
                                    Console.WriteLine("To restore an ISO without an UPDATE partition you need a Redump DAT file and some extracted UPDATE partitions from other ISOs");
                                    break;
                                }

                                var parts = new List<PartitionRecord>();
                                var partition_count = source.ReadBE32(0x40000);
                                for (var i = 0; i < partition_count; i++) parts.Add(new PartitionRecord() { offset = source.ReadBE32(0x40020 + i * 8) * 4, type = (PartitionType)source.ReadBE32(0x40020 + i * 8 + 4) });
                                if (parts.TrueForAll(x => x.type != PartitionType.UPDATE)) parts.Add(new PartitionRecord() { type = PartitionType.UPDATE, offset = 0x50000 });
                                parts.Sort((x, y) => x.offset.CompareTo(y.offset));
                                Array.Clear(original_header, 0x40020, 32);
                                partition_count = parts.Count;
                                for (var i = 0; i < partition_count; i++)
                                {
                                    BigEndian.GetBytes((uint)(parts[i].offset / 4), original_header, 0x40020 + i * 8);
                                    BigEndian.GetBytes((uint)(parts[i].type), original_header, 0x40020 + i * 8 + 4);
                                }
                                BigEndian.GetBytes((uint)(parts.Count), original_header, 0x40000);
                                //File.WriteAllBytes("original_header", original_header);
                            }
                            var game_header = original_header.SubArray(0, original_header.Length);
                            new Partition(source, GetPartitions(source).First(x => x.type == PartitionType.DATA).offset).Read(0, 256).CopyTo(game_header, 0);
                            Array.Clear(game_header, 0x60, 2);
                            //File.WriteAllBytes("game_header", game_header);
                            var headers = new[] { original_header, game_header };
                            var crc_ready = false;
                            uint header_crc;
                            uint tail_crc = 0;
                            uint original_update_crc = 0;
                            foreach (var header in headers)
                            {
                                var header_stream = new MemoryStream(header);
                                header_crc = CRC.Compute(header);
                                var junk = new Junk(header_stream.ReadString(0, 4), (int)header_stream.Read(6, 1)[0], source.Length);
                                foreach (var update_partition in update_partitions)
                                {
                                    IList<RedumpRecord> redump_records;
                                    if (crc_ready)
                                    {
                                        var update_crc = update_partition == source_file_path ? original_update_crc : uint.Parse(update_partition.Substring(update_partition.Length - 8), System.Globalization.NumberStyles.HexNumber);
                                        var full_crc = ~CRC.Combine(~header_crc, ~update_crc, 0xF800000 - 0x50000);
                                        full_crc = ~CRC.Combine(~full_crc, ~tail_crc, source.Length - 0xf800000);
                                        redump_records = redump.Where(x => x.crc == full_crc).ToList();
                                        if (redump_records.Count == 0) continue;
                                    }
                                    Console.WriteLine("Using UPDATE partition from file " + update_partition);
                                    var crc = new CRC();
                                    var sha1 = SHA1.Create();
                                    using (var target = new CryptoStream(new CryptoStream(iso_files.Length > 1 ? (Stream)new VoidStream() : File.Create(target_path), sha1, CryptoStreamMode.Write), crc, CryptoStreamMode.Write))
                                    {
                                        target.Write(header, 0, 0x50000);
                                        crc.Initialize();
                                        var partitions = GetPartitions(header_stream);
                                        using (var update_source = update_partition == source_file_path ? OpenFile(update_partition) : File.OpenRead(update_partition))
                                        {
                                            for (var partition_index = 0; partition_index < partitions.Count; partition_index++)
                                            {
                                                var partition = partitions[partition_index];
                                                Partition source_partition;
                                                if (partition.offset == 0x50000) source_partition = new Partition(update_source, update_partition == source_file_path ? 0x50000 : 0);
                                                else source_partition = new Partition(source, partition.offset);
                                                var target_partition = new Partition(target, source_partition.Header, true);
                                                Console.WriteLine("processing partition " + partition.type + " " + source_partition.Id);
                                                source_partition.Copy(0, target_partition, source_partition.Length, 5);
                                                var space_start = partition.offset + source_partition.PartitionLength;
                                                var space_size = (partition_index + 1 < partitions.Count ? partitions[partition_index + 1].offset : source.Length) - partition.offset - source_partition.PartitionLength;
                                                if (partition.offset == 0x50000)
                                                {
                                                    VoidStream.Stream.Copy(target, space_size, 0);
                                                    target.Flush();
                                                    if (update_partition == source_file_path) original_update_crc = crc.Value;
                                                    crc.Initialize();
                                                }
                                                else
                                                {
                                                    VoidStream.Stream.Copy(target, Math.Min(space_size, 28), 0);
                                                    if (space_size > 28) junk.Copy(space_start + 28, target, space_size - 28, 0);
                                                }
                                            }
                                        }
                                        tail_crc = crc.Value;
                                    }
                                    crc_ready = true;
                                    //try
                                    //{
                                    //    Console.WriteLine(
                                    //        header_crc.ToString("X8") + tail_crc.ToString("X8") +
                                    //        " " + BitConverter.ToString(sha1.Hash).Replace("-", ""));
                                    //}
                                    //catch { }

                                    if (redump.Any(x => x.sha1.Equals(0, sha1.Hash, 0, 20)))
                                    {
                                        found = true;
                                        break;
                                    }
                                }
                                if (found) break;
                            }
                        }

                        if (found) Console.WriteLine("Redump match found. The ISO is genuine");
                        else if (has_update_partition) Console.WriteLine("No redump match found. The ISO cannot be verified");
                        else
                        {
                            Console.WriteLine("No redump match found. The ISO cannot be restored");
                            File.Delete(target_path);
                        }

                        if (File.Exists(target_path))
                        {
                            var old_file_path = source_file_path + ".old";
                            Console.WriteLine("renaming");
                            Console.WriteLine(Path.GetFileName(source_file_path) + " -> " + Path.GetFileName(old_file_path));
                            if (File.Exists(old_file_path)) File.Delete(old_file_path);
                            File.Move(source_file_path, old_file_path);

                            if (!found) new_target = Path.GetDirectoryName(new_target) + "/" + Path.GetFileNameWithoutExtension(new_target) + " (unverified)" + Path.GetExtension(new_target);
                            Console.WriteLine(Path.GetFileName(target_path) + " -> " + Path.GetFileName(new_target));
                            File.Move(target_path, new_target);
                        }
                    }
                    catch (Partition.H3Error)
                    {
                        Console.WriteLine("H3 checksum error. Either the file is corrupt or this is a bug. Please report this error");
                    }
                    //if (iso_files.Length > 1) progress.Print(iso_files.Length - 1);
                }
            }
            Console.WriteLine("FINISHED");
            Console.ReadKey();
        }

        static void ConvertPartitionFiles(string[] update_partitions)
        {
            var progress = new Progress(update_partitions.Count(), 5);
            for (var i = 0; i < update_partitions.Length;i++)
            {
                var uf = update_partitions[i];
                var dest_folder = "update_partitions";
                if (Regex.IsMatch(uf, @"\w{40}_\w_\w{8}")) continue;
                Console.WriteLine("Converting UPDATE partition file " + uf + " to new naming");
                try
                {
                    using (var source = File.OpenRead(uf))
                    {
                        var source_partition = new Partition(source, 0);
                        var name = BitConverter.ToString(source_partition.content_sha1).Replace("-", "") + "_" + (source_partition.korean ? "K" : "N");
                        if (Directory.GetFiles(dest_folder, "*" + name + "*", SearchOption.TopDirectoryOnly)
                            .Where(x => Regex.IsMatch(x, name + @"_\w{8}")).Count() == 0)
                        {
                            name = Path.Combine(dest_folder, name);
                            var target_crc = new CRC();
                            using (var dest = new CryptoStream(File.Create("temp"), target_crc, CryptoStreamMode.Write))
                            {
                                var dp = new Partition(dest, source_partition.Header, true);
                                source_partition.Copy(dp, source_partition.Length, 0);
                            }
                            long space_size = 0xf800000 - source_partition.PartitionLength - 0x50000;
                            var crc1 = target_crc.Value;
                            target_crc = new CRC();
                            using (var t = new CryptoStream(new VoidStream(), target_crc, CryptoStreamMode.Write)) VoidStream.Stream.Copy(t, space_size, 0);
                            crc1 = ~CRC.Combine(~crc1, ~target_crc.Value, space_size);
                            File.Move("temp", name + "_" + crc1.ToString("X8"));
                        }
                    }
                    File.Delete(uf);
                }
                catch (Partition.H3Error)
                {
                    Console.WriteLine("H3 checksum error. Either the file is corrupt or this is a bug. Please report this error");
                }
                progress.Print(update_partitions.Length - i);
            }
            Console.WriteLine();
        }

        static Stream OpenFile(string path)
        {
            var file = (Stream)File.OpenRead(path);
            if (file.Length >= 256 && file.ReadString(0, 4) == "WBFS") return new Wbfs(file);
            if (file.Length >= 256 && file.ReadBE32(0x18) == 0x5D1C9EA3) return file;
            Console.WriteLine("Not a Wii ISO/WBFS");
            return null;
        }

        static bool IsWiiISO(string path)
        {
            using (var source_file = File.OpenRead(path)) return source_file.Length > 256 && source_file.ReadBE32(0x18) == 0x5D1C9EA3;
        }

        static bool IsWiiWBFS(string path)
        {
            using (var source_file = File.OpenRead(path))
            {
                if (source_file.Length < 256 || source_file.ReadString(0, 4) != "WBFS") return false;
                var source = (Stream)new Wbfs(source_file);
                return source.ReadBE32(0x18) == 0x5D1C9EA3;
            }
        }

        class PartitionRecord
        {
            public PartitionType type;
            public long offset;
        }

        static IList<PartitionRecord> GetPartitions(Stream source)
        {
            var partitions = new List<PartitionRecord>();
            for (var partition_table_index = 0; partition_table_index < 4; partition_table_index++)
            {
                var partitions_count = (int)source.ReadBE32(0x40000 + partition_table_index * 8);
                if (partitions_count == 0) continue;
                var table_offset = source.ReadBE32(0x40000 + partition_table_index * 8 + 4) * 4;
                for (var partition_index = 0; partition_index < partitions_count; partition_index++)
                {
                    var partition_offset = source.ReadBE32(table_offset + partition_index * 8) * 4;
                    var partition_type = (PartitionType)source.ReadBE32(table_offset + partition_index * 8 + 4);
                    partitions.Add(new PartitionRecord() { type = partition_type, offset = partition_offset });
                }
            }
            return partitions;
        }
        static void WritePartitionTable(IList<PartitionRecord> table)
        {

        }
        static void PrintSyntax()
        {
            Console.WriteLine("1. Drop folder with ISOs/wbfs on this exe to extract their update partitions");
            Console.WriteLine("2. Put redump DAT file into UltimateUnscrubber_files");
            Console.WriteLine("3. Drop ISO/wbfs on this exe to unscrub it");
            Console.WriteLine("Steps 1 and 2 are optional");
           
            Console.ReadKey();
            return;
        }
        static bool IsISOEnrypted(Stream iso)
        {
            var table_offset = iso.ReadBE32(0x40004) * 4;
            var partition_offset = iso.ReadBE32(table_offset) * 4;
            return !iso.Read(partition_offset + 0x20000 + 0x26C, 20).IsUniform(0, 20, 0);
        }
    }
}
