using System;
using System.IO;
using System.Text;

namespace UltimateUnscrubber
{
    class Junk : Stream
    {
        public override long Position { get { return position; } set { position = value; } }
        long position;
        public override long Length { get { return length; } }
        long length;
        byte[] id;
        int disc;
        byte[] junk = new byte[0x40000];
        int current_junk_index = -1;

        public Junk(string ID, int disc, long length)
        {
            id = Encoding.ASCII.GetBytes(ID);
            this.disc = disc;
            this.length = length;
        }

        public override int Read(byte[] buffer, int offset, int size)
        {
            while (size > 0)
            {
                var junk_index = (int)(position / junk.Length);
                if (current_junk_index != junk_index)
                {
                    current_junk_index = junk_index;
                    GetJunkBlock((uint)current_junk_index, id, (byte)disc, junk);
                    var junk_size = (int)Math2.Clamp(0, Math2.Align(length, 0x8000) - (long)junk_index * junk.Length, junk.Length);
                    Array.Clear(junk, junk_size, junk.Length - junk_size);
                }
                var junk_offset = (int)(position % junk.Length);
                var junk_copy_size = Math.Min(size, junk.Length - junk_offset);
                Array.Copy(junk, junk_offset, buffer, offset, junk_copy_size);
                offset += junk_copy_size;
                size -= junk_copy_size;
                position += junk_copy_size;
            }
            return size;
        }

        uint[] numArray = new uint[0x824];
        void GetJunkBlock(uint block, byte[] ID, byte disc, byte[] buffer)
        {
            Array.Clear(numArray, 0, numArray.Length);
            int num2 = 0;
            uint sample = 0;
            block = (block * 8) * 0x1ef29123;
            for (var i = 0; i < 0x40000; i += 4)
            {
                if ((i & 0x7fff) == 0)
                {
                    sample = (uint)(((((ID[2] << 8) | ID[1]) << 0x10) | ((ID[3] + ID[2]) << 8)) | (ID[0] + ID[1]));
                    sample = ((sample ^ disc) * 0x260bcd5) ^ block;
                    a10002710(sample, numArray);
                    num2 = 520;
                    block += 0x1ef29123;
                }
                num2++;
                if (num2 == 0x209)
                {
                    a100026e0(numArray);
                    num2 = 0;
                }
                buffer[i] = (byte)(numArray[num2] >> 0x18);
                buffer[i + 1] = (byte)(numArray[num2] >> 0x12);
                buffer[i + 2] = (byte)(numArray[num2] >> 8);
                buffer[i + 3] = (byte)numArray[num2];
            }
        }
        void a10002710(uint sample, uint[] buffer)
        {
            int num2;
            uint num = 0;
            for (num2 = 0; num2 != 0x11; num2++)
            {
                for (int i = 0; i < 0x20; i++)
                {
                    sample *= 0x5d588b65;
                    num = (num >> 1) | (++sample & 0x80000000);
                }
                buffer[num2] = num;
            }
            buffer[0x10] ^= (buffer[0] >> 9) ^ (buffer[0x10] << 0x17);
            for (num2 = 1; num2 != 0x1f9; num2++)
            {
                buffer[num2 + 0x10] = ((buffer[num2 - 1] << 0x17) ^ (buffer[num2] >> 9)) ^ buffer[num2 + 15];
            }
            for (num2 = 0; num2 < 3; num2++)
            {
                a100026e0(buffer);
            }
        }
        void a100026e0(uint[] buffer)
        {
            int index = 0;
            while (index != 0x20)
            {
                buffer[index] ^= buffer[index + 0x1e9];
                index++;
            }
            while (index != 0x209)
            {
                buffer[index] ^= buffer[index - 0x20];
                index++;
            }
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return true; } }
        public override bool CanWrite { get { return false; } }
        public override void Flush() { throw new NotImplementedException(); }
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
        public override void Write(byte[] buffer, int offset, int count) { throw new NotImplementedException(); }
    }
}
