using System;
using System.Text;

namespace UltimateUnscrubber
{
    public class JunkStream
    {
        public long Position;
        bool hashed;
        byte[] id;
        byte[] junk = new byte[0x40000];
        int current_junk_index = -1;
        uint[] numArray = new uint[0x824];
        long end_offset;
        int disc;

        public JunkStream(string ID, int disc, bool hashed, long end_offset)
        {
            this.hashed = hashed;
            this.end_offset = end_offset;
            this.disc = disc;
            id = Encoding.ASCII.GetBytes(ID);
        }

        public void Read(byte[] data, int offset, int size)
        {
            while (size > 0)
            {
                var writing_hash = hashed && Position % 0x8000 < 0x400;
                var to_write = (writing_hash ? 0x400 : 0x8000) - (int)(Position % 0x8000);
                to_write = Math.Min(to_write, size);
                if (writing_hash) Array.Clear(data, offset, to_write);
                else
                {
                    var unhashed_offset = Unhash(Position);
                    var junk_index = (int)(unhashed_offset / 0x40000);
                    var junk_offset = (int)(unhashed_offset % 0x40000);
                    if (current_junk_index != junk_index)
                    {
                        current_junk_index = junk_index;
                        GetJunkBlock((uint)current_junk_index, id, (byte)disc, junk);
                        var junk_end_offset = (int)Math.Min(Unhash(end_offset) / 0x8000 * 0x8000 - (unhashed_offset-junk_offset), 0x40000);
                        junk_end_offset = Math.Max(junk_end_offset, 0);
                        Array.Clear(junk, junk_end_offset, 0x40000 - junk_end_offset);
                    }
                    to_write = Math.Min(to_write, 0x40000 - junk_offset);
                    Array.Copy(junk, junk_offset, data, offset, to_write);
                }
                offset += to_write;
                size -= to_write;
                Position += to_write;
            }
        }

        long Unhash(long offset)
        {
            if (hashed) return offset / 0x8000 * 0x7c00 + Math.Max(offset % 0x8000 - 0x400, 0);
            else return offset;
        }

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
    }
}
