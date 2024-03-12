
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public class ZipItFileHelper
{
    // https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
    // https://games.greggman.com/game/zip-rant/
    
    public const uint ZipLocalFileHeaderSignature = 0x04034b50;
    public const uint ZipLocalFileHeaderSize = 30;

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 30)]
    public struct ZipLocalFileHeader
    {
        public uint signature;
        public ushort version;
        public ushort bitflags;
        public ushort compressionMethod;
        public ushort lastModFileTime;
        public ushort lastModFileDate;
        public uint crc32;
        public uint compressedSize;
        public uint uncompressedSize;
        public ushort fileNameLength;
        public ushort extraFieldLength;
    }

    public const uint ZipCentralFileHeaderSignature = 0x02014b50;
    public const uint ZipCentralFileHeaderSize = 46;

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 46)]
    public struct ZipCentralFileHeader
    {
        public uint signature;
        public ushort versionUsed;
        public ushort versionRequired;
        public ushort bitflags;
        public ushort compressionMethod;
        public ushort lastModeFileTime;
        public ushort lastModFileDate;
        public uint crc32;
        public uint compressedSize;
        public uint uncompressedSize;
        public ushort fileNameLength;
        public ushort extraFieldLength;
        public ushort fileCommentLength;
        public ushort diskNumberStart;
        public ushort internalFileAttributes;
        public uint externalFileAttributes;
        public uint relativeOffsetOfLocalHeader;
    }

    public const uint ZipEndOfCentralDirHeaderSignature = 0x06054b50;
    public const uint ZipEndOfCentralDirHeaderSize = 22;

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 22)]
    public struct ZipEndOfCentralDirHeader
    {
        public uint signature;
        public ushort diskNumberCurrent;
        public ushort diskNumberCentral;
        public ushort diskEntryCountCurrent;
        public ushort diskEntryCountCentral;
        public uint centralDirSize;
        public uint centralDirOffset;
        public ushort fileCommentLength;
    }

    // https://unix.stackexchange.com/questions/14705/the-zip-formats-external-file-attribute

    public const int S_IFIFO = 0x1000; // named pipe (fifo)
    public const int S_IFCHR = 0x2000; // character special
    public const int S_IFDIR = 0x4000; // directory
    public const int S_IFBLK = 0x6000; // block special
    public const int S_IFREG = 0x8000; // regular
    public const int S_IFLNK = 0xA000; // symbolic link
    public const int S_IFSOCK = 0xC000; // socket

    public const int S_ISUID = 0x800; // set user id on execution
    public const int S_ISGID = 0x400; // set group id on execution
    public const int S_ISTXT = 0x200; // sticky bit
    public const int S_IRWXU = 0x1C0; // RWX mask for owner
    public const int S_IRUSR = 0x100; // R for owner
    public const int S_IWUSR = 0x80;  // W for owner
    public const int S_IXUSR = 0x40;  // X for owner
    public const int S_IRWXG = 0x38;  // RWX mask for group
    public const int S_IRGRP = 0x20;  // R for group
    public const int S_IWGRP = 0x10;  // W for group
    public const int S_IXGRP = 0x8;   // X for group
    public const int S_IRWXO = 0x7;   // RWX mask for other
    public const int S_IROTH = 0x4;   // R for other
    public const int S_IWOTH = 0x2;   // W for other
    public const int S_IXOTH = 0x1;   // X for other
    public const int S_ISVTX = 0x200; // save swapped text even after use

    static uint ConvertSymbolicPermissionsToOctal(string permissions)
    {
        if (permissions.Length == 9) {
            Console.WriteLine("updating permissions length");
            permissions = "-" + permissions;
        }

        if (permissions.Length != 10)
            throw new ArgumentException("Invalid permission length. Permission string should be 10 characters long.");

        uint octalPermissions = 0;

        // Calculate the permission for user
        octalPermissions += (permissions[1] == 'r' ? 4u : 0u);
        octalPermissions += (permissions[2] == 'w' ? 2u : 0u);
        octalPermissions += (permissions[3] == 'x' ? 1u : 0u);
        
        octalPermissions <<= 3; // Shift left for the next group

        // Calculate the permission for group
        octalPermissions += (permissions[4] == 'r' ? 4u : 0u);
        octalPermissions += (permissions[5] == 'w' ? 2u : 0u);
        octalPermissions += (permissions[6] == 'x' ? 1u : 0u);
        
        octalPermissions <<= 3; // Shift left for others

        // Calculate the permission for others
        octalPermissions += (permissions[7] == 'r' ? 4u : 0u);
        octalPermissions += (permissions[8] == 'w' ? 2u : 0u);
        octalPermissions += (permissions[9] == 'x' ? 1u : 0u);

        return octalPermissions;
    }
    
    public static void SetUnixFilePermissions(string filePath, string pattern, string permissions)
    {
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite))
        using (BinaryReader br = new BinaryReader(fs))
        {
            long fileLength = fs.Length;
            while (fs.Position < fileLength)
            {
                long headerStartPosition = fs.Position;
                uint signature = br.ReadUInt32();
                fs.Seek(-4, SeekOrigin.Current); // Move back to the start of the signature

                if (signature == ZipLocalFileHeaderSignature)
                {
                    var header = ReadStruct<ZipLocalFileHeader>(br);
                    string fileName = Encoding.UTF8.GetString(br.ReadBytes(header.fileNameLength));
                    fs.Seek(header.compressedSize + header.extraFieldLength, SeekOrigin.Current);
                }
                else if (signature == ZipCentralFileHeaderSignature)
                {
                    var header = ReadStruct<ZipCentralFileHeader>(br);
                    byte[] fileNameBytes = br.ReadBytes(header.fileNameLength);
                    string fileName = Encoding.UTF8.GetString(fileNameBytes);

                    Console.WriteLine("File: {0}", fileName);

                    if (Regex.IsMatch(fileName, pattern))
                    {
                        uint fileAttributes = 0x0001; // DOS attributes (lower byte)
                        uint unixFileType = S_IFREG; // regular file
                        uint unixPermissions = ConvertSymbolicPermissionsToOctal(permissions);
                        uint unixAttributes = unixFileType | unixPermissions;
                        fileAttributes |= unixAttributes << 16;
                        Console.WriteLine($"Updated file external attributes: {fileAttributes:X8}");

                        header.versionUsed = (ushort)((header.versionUsed & 0x00FF) | (0x03 << 8)); // Unix
                        header.externalFileAttributes = fileAttributes;
                        
                        fs.Seek(headerStartPosition, SeekOrigin.Begin);
                        WriteStruct(fs, header);
                        fs.Seek(header.fileNameLength, SeekOrigin.Current);
                    }

                    fs.Seek(header.extraFieldLength + header.fileCommentLength, SeekOrigin.Current);
                }
                else if (signature == ZipEndOfCentralDirHeaderSignature)
                {
                    break; // No need to continue reading after the end of central directory record
                }
                else
                {
                    Console.WriteLine($"Unknown Header: 0x{signature:X8}");
                    break;
                }
            }
        }
    }

    private static T ReadStruct<T>(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        }
        finally
        {
            handle.Free();
        }
    }

    private static void WriteStruct<T>(FileStream fs, T theStruct) where T : struct
    {
        byte[] bytes = new byte[Marshal.SizeOf(typeof(T))];
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        Marshal.StructureToPtr(theStruct, handle.AddrOfPinnedObject(), true);
        fs.Write(bytes, 0, bytes.Length);
        handle.Free();
    }
}
"@ -Language CSharp

function Set-ZipItUnixFilePermissions
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $ZipFilePath,

        [Parameter(Position = 1, Mandatory = $true)]
        [string] $FilePattern,

        [Parameter(Position = 2, Mandatory = $true)]
        [string] $FilePermissions
    )

    [ZipItFileHelper]::SetUnixFilePermissions($ZipFilePath, $FilePattern, $FilePermissions)
}
