using System;
using System.IO;

namespace UltimateUnscrubber
{
    class Wbfs : Stream
    {
        Stream stream;
        int cluster_size;
        byte[] clusters_table;
        public override long Position { get { return position; } set { position = value; } }
        long position;
        public override long Length { get { return length; } }
        long length;

        public Wbfs(Stream stream)
        {
            this.stream = stream;
            cluster_size = 1 << stream.Read(9, 1)[0];
            clusters_table = stream.Read((1 << stream.Read(8, 1)[0]) + 0x100, (int)(4699979776 * 2 / cluster_size * 2));
            for (var i = 0; i < clusters_table.Length / 2; i++) if (BigEndian.ToUInt16(clusters_table, i * 2) != 0) length = (long)(i + 1) * cluster_size;
            length = length <= 4699979776 ? 4699979776 : 8511160320;
        }

        public override int Read(byte[] buffer, int offset, int size)
        {
            while (size > 0)
            {
                var cluster_index = (int)(position / cluster_size);
                var in_cluster_offset = (int)(position % cluster_size);
                var cluster_wbfs_index = BigEndian.ToUInt16(clusters_table, cluster_index * 2);
                var cluster_copy_size = Math.Min(cluster_size - in_cluster_offset, size);
                if (cluster_wbfs_index == 0) Array.Clear(buffer, offset, cluster_copy_size);
                else stream.Read((long)cluster_wbfs_index * cluster_size + in_cluster_offset, buffer, offset, cluster_copy_size);
                offset += cluster_copy_size;
                size -= cluster_copy_size;
                position += cluster_copy_size;
            }
            return size;
        }

        public override bool CanRead
        {
            get { throw new NotImplementedException(); }
        }

        public override bool CanSeek
        {
            get { throw new NotImplementedException(); }
        }

        public override bool CanWrite
        {
            get { throw new NotImplementedException(); }
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
        public override void Close()
        {
            stream.Close();
            base.Close();
        }
    }
}