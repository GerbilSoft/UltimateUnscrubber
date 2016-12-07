using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UltimateUnscrubber
{
    class Partition : Stream
    {
        enum TransformType { Encrypt, Decrypt };
        public class H3Error : Exception { }

        public override long Position { get { return position; } set { position = value; } }
        long position;
        public override long Length { get { return length; } }
        long length;
        public long PartitionLength { get { return data_size + data_offset; } }
        Stream stream;
        Aes aes = Aes.Create();
        SHA1 sha1 = SHA1.Create();
        long data_size;
        public string Id;
        int disc;
        bool is_encrypted;
        Junk junk;
        int data_offset;
        long volume_offset;
        byte[] group = new byte[0x8000 * 64];
        int current_group_index = -1;
        byte[] h3_table;
        bool writeable;
        public bool korean;
        public byte[] content_sha1;
        public byte[] Header { get { return stream.Read(volume_offset - data_offset, data_offset); } }

        public Partition(Stream stream, long partition_offset)
        {
            writeable = false;
            Initialize(stream, stream, partition_offset);
            volume_offset = partition_offset + data_offset;
            is_encrypted = !stream.Read(volume_offset + 0x26C, 20).IsUniform(0, 20, 0);

            var first_block = stream.Read(volume_offset, 0x8000);
            if (is_encrypted) TransformBlock(first_block, 0, TransformType.Decrypt);
            Id = Encoding.ASCII.GetString(first_block, 0x400, 4);
            disc = first_block[0x406];
            junk = new Junk(Id, disc, length);
        }
        public Partition(Stream stream, byte[] header, bool encrypted)
        {
            writeable = true;
            Initialize(stream, new MemoryStream(header), 0);
            is_encrypted = encrypted;
            stream.Write(header, 0, header.Length);
        }

        void Initialize(Stream stream, Stream header_stream, long header_offset)
        {
            this.stream = stream;
            aes.Padding = PaddingMode.None;

            data_offset = (int)header_stream.ReadBE32(header_offset + 0x2b8) * 4;
            data_size = header_stream.ReadBE32(header_offset + 0x2bc) * 4;
            length = data_size / 0x8000 * 0x7c00;
            h3_table = header_stream.Read(header_offset + header_stream.ReadBE32(header_offset + 0x2B4) * 4, 0x18000);

            var tmd_offset = header_stream.ReadBE32(header_offset + 0x2a8) * 4;
            content_sha1 = header_stream.Read(header_offset + tmd_offset + 0x1e4 + 0x10, 20);

            var key = header_stream.Read(header_offset + 0x1bf, 16);
            korean = header_stream.Read8(header_offset + 0x1f1) == 1;
            aes.Key = korean ? BigNumber.ParseHex("63b82bb4f4614e2e13f2fefbba4c9b7e") : BigNumber.ParseHex("ebe42a225e8593e448d9c5457381aaf7");
            var iv = header_stream.Read(header_offset + 0x1dc, 16);
            Array.Clear(iv, 8, 8);
            aes.IV = iv;
            using (var cryptor = aes.CreateDecryptor()) cryptor.TransformBlock(key, 0, 16, key, 0);
            aes.Key = key;
        }
        public override int Read(byte[] buffer, int offset, int size)
        {
            if (!CanRead) throw new Exception();
            while (size > 0)
            {
                var group_index = (int)(position / (0x7c00 * 64));
                if (current_group_index != group_index)
                {
                    current_group_index = group_index;
                    Array.Clear(group, 0, group.Length);
                    stream.Read(volume_offset + (long)group_index * group.Length, group, 0, (int)Math.Min(group.Length, data_size - (long)group_index * group.Length));
                    if (is_encrypted) for (var i = 0; i < 64; i++) TransformBlock(group, i, TransformType.Decrypt);
                    for (var i = 0; i < 64; i++) if (!IsValidData(group, i)) junk.Read((long)group_index * (0x7c00 * 64) + i * 0x7c00, group, i * 0x8000 + 0x400, 0x7c00);
                    HashGroup(group);
                }
                var block_copy_size = (int)Math.Min(0x7c00 - position % 0x7c00, size);
                Array.Copy(group, (int)((position + (position / 0x7c00 + 1) * 0x400) % group.Length), buffer, offset, block_copy_size);
                offset += block_copy_size;
                size -= block_copy_size;
                position += block_copy_size;
            }
            return size;
        }
        public override void Write(byte[] buffer, int offset, int size)
        {
            if (!CanWrite) throw new Exception();
            while (size > 0)
            {
                var group_index = (int)(position / (0x7c00 * 64));
                current_group_index = group_index;
                var block_copy_size = (int)Math.Min(0x7c00 - position % 0x7c00, size);
                Array.Copy(buffer, offset, group, (int)((position + (position / 0x7c00 + 1) * 0x400) % group.Length), block_copy_size);
                offset += block_copy_size;
                size -= block_copy_size;
                position += block_copy_size;
                var group_offset = (long)group_index * group.Length;
                var group_data_size = (int)Math.Min(group.Length, data_size - group_offset);
                if ((position + Math2.DivSpec(position, 0x7c00) * 0x400) - group_offset == group_data_size)
                {
                    Array.Clear(group, group_data_size, group.Length - group_data_size);
                    HashGroup(group);
                    if (is_encrypted) for (var i = 0; i < 64; i++) TransformBlock(group, i, TransformType.Encrypt);
                    stream.Write(group, 0, group_data_size);
                }
            }
        }
        void TransformBlock(byte[] blocks, int index, TransformType transform_type)
        {
            var IV = new byte[16];
            aes.IV = IV;
            if (transform_type == TransformType.Decrypt) Array.Copy(blocks, index * 0x8000 + 0x3d0, IV, 0, 16);
            using (var cryptor = transform_type == TransformType.Decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor())
                cryptor.TransformBlock(blocks, index * 0x8000, 0x400, blocks, index * 0x8000);
            if (transform_type == TransformType.Encrypt) Array.Copy(blocks, index * 0x8000 + 0x3d0, IV, 0, 16);
            aes.IV = IV;
            using (var cryptor = transform_type == TransformType.Decrypt ? aes.CreateDecryptor() : aes.CreateEncryptor())
                cryptor.TransformBlock(blocks, index * 0x8000 + 0x400, 0x7c00, blocks, index * 0x8000 + 0x400);
        }
        bool IsValidData(byte[] buffer, int block_index)
        {
            for (var i = 0; i < 31; i++)
                if (!sha1.ComputeHash(buffer, block_index * 0x8000 + (i + 1) * 0x400, 0x400).Equals(0, buffer, block_index * 0x8000 + i * 20, 20))
                    return false;
            return true;
        }
        void HashGroup(byte[] group)
        {
            for (var i = 0; i < 64; i++) Array.Clear(group, i * 0x8000, 0x400);
            for (var block_index = 0; block_index < 64; block_index++)
            {
                for (int i = 0; i < 31; i++) sha1.ComputeHash(group, block_index * 0x8000 + (i + 1) * 0x400, 0x400).CopyTo(group, block_index * 0x8000 + i * 20);
                var subgroup_index = block_index / 8;
                var block_in_subgroup_index = block_index % 8;
                var h1 = sha1.ComputeHash(group, block_index * 0x8000, 31 * 20);
                for (var block_in_subgroup_index2 = 0; block_in_subgroup_index2 < 8; block_in_subgroup_index2++)
                {
                    var block_index2 = subgroup_index * 8 + block_in_subgroup_index2;
                    h1.CopyTo(group, block_index2 * 0x8000 + 0x280 + block_in_subgroup_index * 20);
                }
                if (block_in_subgroup_index == 7)
                {
                    var h2 = sha1.ComputeHash(group, block_index * 0x8000 + 0x280, 8 * 20);
                    for (var block_index2 = 0; block_index2 < 64; block_index2++)
                        h2.CopyTo(group, block_index2 * 0x8000 + 0x340 + subgroup_index * 20);
                }
            }
            var h3_1 = sha1.ComputeHash(group, 0x340, 160);
            var h3_2 = h3_table.SubArray(current_group_index * 20, 20);
            if (!sha1.ComputeHash(group, 0x340, 160).Equals(0, h3_table, current_group_index * 20, 20)) throw new H3Error();
        }
        public override bool CanRead { get { return !writeable; } }
        public override bool CanSeek { get { return true; } }
        public override bool CanWrite { get { return writeable; } }
        public override void Flush() { if (Position != Length) throw new NotImplementedException(); }
        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin: Position = offset; break;
                case SeekOrigin.Current: Position += offset; break;
                case SeekOrigin.End: Position = Length - offset; break;
            }
            return Position;
        }
        public override void SetLength(long value) { throw new NotImplementedException(); }
    }
}