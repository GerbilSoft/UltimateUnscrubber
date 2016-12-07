using System;
using System.IO;
using System.Text;

namespace UltimateUnscrubber
{
    partial class Math2
    {
        public static long Clamp(long val, long min, long max) { return Math.Min(Math.Max(min, val), max); }
        public static long Align(long val, long boundry) { return val / boundry * boundry; }
        public static long DivSpec(long number1, long number2) { return number1 / number2 + Clamp(0, number1 % number2, 1); }
    }
    public static class File2
    {
        public static long GetFileSize(string path) { using (var f = File.OpenRead(path)) return f.Length; }
    }
    public static class BigNumber
    {
        public static byte[] ParseHex(string hex)
        {
            hex = hex.Replace(" ", "");
            if (hex.Length % 2 != 0) throw new Exception();
            var buf = new byte[hex.Length / 2];
            for (var i = 0; i < buf.Length; i++)
            {
                buf[i] = byte.Parse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return buf;
        }
    }
    public static class BigEndian
    {
        public static ushort ToUInt16(byte[] data, int offset) { return ChangeEndianness(BitConverter.ToUInt16(data, offset)); }
        public static uint ToUInt32(byte[] data, int offset) { return ChangeEndianness(BitConverter.ToUInt32(data, offset)); }
        public static uint ChangeEndianness(uint x) { x = (x >> 16) | (x << 16); return ((x & 0xFF00FF00) >> 8) | ((x & 0x00FF00FF) << 8); }
        public static ushort ChangeEndianness(ushort x) { return (ushort)((x >> 8) | (x << 8)); }
        public static void GetBytes(uint val, byte[] data, int offset) { BitConverter.GetBytes(ChangeEndianness(val)).CopyTo(data, offset); }
    }
    public class VoidStream : Stream
    {
        public static VoidStream Stream;

        static VoidStream()
        {
            Stream = new VoidStream();
        }

        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }

        public override long Length { get { throw new NotImplementedException(); } }
        public override void SetLength(long value) { throw new NotImplementedException(); }

        public override long Position
        {
            get { throw new NotImplementedException(); }
            set { throw new NotImplementedException(); }
        }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotImplementedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Clear(buffer, offset, count);
            return count;
        }
        public override void Write(byte[] buffer, int offset, int count) { }
        public override void Flush() { }
    }
    public class Progress
    {
        long start;
        int last_percent;
        int step;
        public Progress(long finish, int step)
        {
            this.start = finish;
            this.step = step;
        }

        public void Print(long current)
        {
            var current_percent = (int)((double)(start - current) / start * 100);
            if (current_percent >= last_percent + step)
            {
                Console.WriteLine(current_percent.ToString() + "%");
                last_percent = current_percent;
            }
        }
    }
 
    public static class ExtensionMethods
    {
        public static bool Equals(this byte[] data1, int offset1, byte[] data2, int offset2, int size)
        {
            for (var i = 0; i < size; i++) if (data1[i + offset1] != data2[i + offset2]) return false;
            return true;
        }
        public static bool IsUniform(this byte[] data, int offset, int size, byte value)
        {
            for (var i = 0; i < size; i++) if (data[i + offset] != value) return false;
            return true;
        }

        public static byte Read8(this Stream file, long position) { return file.Read(position, 1)[0]; }
        public static long ReadBE32(this Stream file, long position) { return BigEndian.ToUInt32(file.Read(position, 4), 0); }
        public static int ReadBE16(this Stream file, long position) { return BigEndian.ToUInt16(file.Read(position, 2), 0); }
        public static string ReadString(this Stream file, long position, int length) { return Encoding.ASCII.GetString(file.Read(position, length)); }

        public static byte[] Read(this Stream file, long position, int amount)
        {
            var buffer = new byte[amount];
            file.Read(position, buffer, 0, amount);
            return buffer;
        }
        public static void Read(this Stream file, long position, byte[] buffer, int offset, int amount)
        {
            file.Position = position;
            file.Read(buffer, offset, amount);
        }
        public static void Copy(this Stream source, long position, Stream target, long amount, int progresss_step)
        {
            source.Position = position;
            source.Copy(target, amount, progresss_step);
        }
        public static void Copy(this Stream source, Stream target, long amount, int progresss_step)
        {
            Progress progress = null;
            if (progresss_step != 0) progress = new Progress(amount, progresss_step);
            byte[] copy_buffer = new byte[0x8000 * 64];
            while (amount > 0)
            {
                var to_copy = (int)Math.Min(copy_buffer.Length, amount);
                source.Read(copy_buffer, 0, to_copy);
                target.Write(copy_buffer, 0, to_copy);
                amount -= to_copy;
                if (progress != null) progress.Print(amount);
            }
        }
        public static T[] SubArray<T>(this T[] array, int offset, int length)
        {
            var a = new T[length];
            Array.Copy(array, offset, a, 0, length);
            return a;
        }
    }
}
