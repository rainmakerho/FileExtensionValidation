using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace FileExtensionValidation
{
    public static class FileExtensionValidator
    {
        //https://en.wikipedia.org/wiki/List_of_file_signatures
        //https://www.filesignatures.net/index.php
        //https://www.garykessler.net/library/file_sigs.html
        //https://asecuritysite.com/forensics/magic
        private static Dictionary<string, List<(byte[] Signature, int Offset, int Skip, byte[] SecondSignature)>> fileSignature
            = new Dictionary<string, List<(byte[] Signature, int Offset, int Skip, byte[] SecondSignature)>>() {
        { ".DOC", new List<(byte[], int, int, byte[])> { (new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, 0, 0, new byte[] { }) } },
        { ".DOCX", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04 } , 0, 0, new byte[] { }),
                                (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                            } },
        { ".PDF", new List<(byte[], int, int, byte[])> { (new byte[] { 0x25, 0x50, 0x44, 0x46 } , 0, 0, new byte[] { }) } },
        { ".ZIP", new List<(byte[], int, int, byte[])>
                                {
                                    (new byte[] { 0x50, 0x4B, 0x03, 0x04 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x4C, 0x49, 0x54, 0x55 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x53, 0x70, 0x58 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x57, 0x69, 0x6E, 0x5A, 0x69, 0x70 }, 0, 0, new byte[] { })
                                    }
                                },
        { ".PNG", new List<(byte[], int, int, byte[])> { (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, 0, 0, new byte[] { }),
                                             (new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, 0, 0, new byte[] { }),
                                             (new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 }, 0, 0, new byte[] { }),
                                             (new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 }, 0, 0, new byte[] { })
                                } },
        { ".JPG", new List<(byte[], int, int, byte[])>
                        {
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 }, 0, 6, new byte[] { 0x45, 0x78, 0x69, 0x66, 0x00, 0x00}),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE2 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE3 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xDB }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xEE }, 0, 0, new byte[] { }),
                            }
                        },
        { ".JPEG", new List<(byte[], int, int, byte[])>
                            {
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, 0, 0, new byte[] { }),
                                 (new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 }, 0, 6, new byte[] { 0x45, 0x78, 0x69, 0x66, 0x00, 0x00}),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE2 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xE3 }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xDB }, 0, 0, new byte[] { }),
                                (new byte[] { 0xFF, 0xD8, 0xFF, 0xEE }, 0, 0, new byte[] { }),
                            }
                            },
        { ".XLS",new List<(byte[], int, int, byte[])>
                                {
                                    (new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x09, 0x08, 0x10, 0x00, 0x00, 0x06, 0x05, 0x00 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x10}, 512, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x1F}, 512, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x22}, 512, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x23}, 512, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x28}, 512, 0, new byte[] { }),
                                    (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x29}, 512, 0, new byte[] { })
                                }
                                },
        { ".XLSX", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04 } , 0, 0, new byte[] { }),
                                        (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                } },
        { ".GIF", new List<(byte[], int, int, byte[])> { (new byte[] { 0x47, 0x49, 0x46, 0x38 }, 0, 0, new byte[] { }) } },
        { ".7Z",new List<(byte[], int, int, byte[])> { (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, 0, 0, new byte[] { }) } },
        { ".BMP", new List<(byte[], int, int, byte[])> { (new byte[] { 0x42, 0x4D }, 0, 0, new byte[] { }) } },
        { ".TIF",new List<(byte[], int, int, byte[])> { (new byte[] { 0x49, 0x20, 0x49 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x4D, 0x4D, 0x00, 0x2A }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x4D, 0x4D, 0x00, 0x2B }, 0, 0, new byte[] { }),
                                }
                              },
        { ".TIFF",new List<(byte[], int, int, byte[])> { (new byte[] { 0x49, 0x20, 0x49 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x49, 0x49, 0x2A, 0x00 }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x4D, 0x4D, 0x00, 0x2A }, 0, 0, new byte[] { }),
                                    (new byte[] { 0x4D, 0x4D, 0x00, 0x2B }, 0, 0, new byte[] { }),
                                }
                              },
        { ".RTF", new List<(byte[], int, int, byte[])> { (new byte[] { 0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31 },0, 0, new byte[] { })
                                }
                               },
        { ".PPT", new List<(byte[], int, int, byte[])> { (new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, 0, 0, new byte[] { }),
                                (new byte[] { 0x00, 0x6E, 0x1E, 0xF0}, 512, 0, new byte[] { }),
                                (new byte[] { 0x0F, 0x00, 0xE8, 0x03}, 512, 0, new byte[] { }),
                                (new byte[] { 0xA0, 0x46, 0x1D, 0xF0}, 512, 0, new byte[] { }),
                                (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x0E, 0x00, 0x00, 0x00}, 512, 0, new byte[] { }),
                                (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x1C, 0x00, 0x00, 0x00}, 512, 0, new byte[] { }),
                                (new byte[] { 0xFD, 0xFF, 0xFF, 0xFF, 0x43, 0x00, 0x00, 0x00}, 512, 0, new byte[] { }),
                                }
                                },
        { ".PPTX", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".ODF", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".ODG", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".ODP", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".ODS", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".ODT", new List<(byte[], int, int, byte[])> { (new byte[] { 0x50, 0x4B, 0x03, 0x04}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x05, 0x06}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x50, 0x4B, 0x07, 0x08}, 0, 0, new byte[] { }),
                                }
                                },
        { ".MPG", new List<(byte[], int, int, byte[])> { (new byte[] { 0x00, 0x00, 0x01, 0xBA}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x00, 0x00, 0x01, 0xB3}, 0, 0, new byte[] { }),
                                }
                                },
        { ".MPEG", new List<(byte[], int, int, byte[])> { (new byte[] { 0x00, 0x00, 0x01, 0xBA}, 0, 0, new byte[] { }),
                                    (new byte[] { 0x00, 0x00, 0x01, 0xB3}, 0, 0, new byte[] { }),
                                }
                                },
        { ".AVI", new List<(byte[], int, int, byte[])> { (new byte[] { 0x52, 0x49, 0x46, 0x46}, 0, 0, new byte[] { }),
                                }
                                },
        { ".WMV", new List<(byte[], int, int, byte[])> { (new byte[] { 0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}, 0, 0, new byte[] { }),
                                }
                                },
        { ".RM", new List<(byte[], int, int, byte[])> { (new byte[] { 0x2E, 0x52, 0x4D, 0x46}, 0, 0, new byte[] { }),
                                }
                                },
        { ".MOV", new List<(byte[], int, int, byte[])> { (new byte[] { 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x6D, 0x6F, 0x6F, 0x76}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x66, 0x72, 0x65, 0x65}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x6D, 0x64, 0x61, 0x74}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x77, 0x69, 0x64, 0x65}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x70, 0x6E, 0x6F, 0x74}, 4, 0, new byte[] { }),
                                            (new byte[] { 0x73, 0x6B, 0x69, 0x70}, 4, 0, new byte[] { })
                                }
                                },
        { ".MKV", new List<(byte[], int, int, byte[])> { (new byte[] { 0x1A, 0x45, 0xDF, 0xA3}, 0, 0, new byte[] { })                                            
                                }
                                },
        { ".RAR", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }, 0, 0, new byte[] { })
                                }
                                },
        { ".3GP", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70 }, 0, 0, new byte[] { }),
                                           (new byte[] { 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70 }, 0, 0, new byte[] { }),
                                           (new byte[] { 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70}, 4, 0, new byte[] { })
                                }
                                },
        { ".MP3", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x49, 0x44, 0x33 }, 0, 0, new byte[] { }),
                                           (new byte[] { 0xFF, 0xFB }, 0, 0, new byte[] { })
                                }
                                },
        { ".WAV", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x52, 0x49, 0x46, 0x46 }, 0, 0, new byte[] { })
                                }
                                },
        { ".MP4", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x66, 0x74, 0x79, 0x70 }, 4, 0, new byte[] { })                                           
                                }
                                },
        { ".M4V", new List<(byte[], int, int, byte[])>{ (new byte[] { 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32 }, 4, 0, new byte[] { }),
                                           (new byte[] { 0x66, 0x74, 0x79, 0x70, 0x4D, 0x34, 0x56, 0x20 }, 4, 0, new byte[] { })
                                }
                                }
        };
        
        public static bool IsValidFileExtension(string fileName, byte[] fileData, byte[] allowedChars)
        {
            if (string.IsNullOrEmpty(fileName) || fileData == null || fileData.Length == 0)
            {
                return false;
            }

            bool flag = false;
            string ext = Path.GetExtension(fileName);
            if (string.IsNullOrEmpty(ext))
            {
                return false;
            }

            ext = ext.ToUpperInvariant();

            if (ext.Equals(".TXT") || ext.Equals(".CSV") || ext.Equals(".PRN"))
            {
                foreach (byte b in fileData)
                {                    
                    if (b > 0xFF)
                    {
                        if (allowedChars != null)
                        {
                            if (!allowedChars.Contains(b))
                            {
                                return false;
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                }

                return true;
            }

            if (!fileSignature.ContainsKey(ext))
            {
                return false;
            }

            List<(byte[] Signature, int Offset, int Skip, byte[] SecondSignature)> sigs = fileSignature[ext];
            foreach (var sig in sigs)
            {
                byte[] b = sig.Signature;
                int offset = sig.Offset;
                var curFileSig = new byte[b.Length];
                Array.Copy(fileData.Skip(offset).ToArray(), curFileSig, b.Length);
                flag = curFileSig.SequenceEqual(b);
                int skip = sig.Skip;
                if (skip > 0 && flag)
                {
                    byte[] secondSignature = sig.SecondSignature;
                    var secondFileSig = new byte[secondSignature.Length];
                    Array.Copy(fileData.Skip(skip).ToArray(), secondFileSig, secondSignature.Length);
                    flag = secondFileSig.SequenceEqual(secondSignature);
                }
                if (flag) break;
            }

            return flag;
        }

        public static bool IsValidFileExtension(string fileName, FileStream fs, byte[] allowedChars)
        {
            bool flag = false;
            string ext = Path.GetExtension(fileName);
            if (string.IsNullOrEmpty(ext))
            {
                return false;
            }

            ext = ext.ToUpperInvariant();

            if (ext.Equals(".TXT") || ext.Equals(".CSV") || ext.Equals(".PRN"))
            {
                var fileData = new byte[fs.Length];
                fs.Read(fileData, 0, Convert.ToInt32(fs.Length));

                foreach (byte b in fileData)
                {
                    if (b > 0x7F)
                    {
                        if (allowedChars != null)
                        {
                            if (!allowedChars.Contains(b))
                            {
                                return false;
                            }
                        }
                        else
                        {
                            return false;
                        }
                    }
                }

                return true;
            }

            if (!fileSignature.ContainsKey(ext))
            {
                return false;
            }

            List<(byte[] Signature, int Offset, int Skip, byte[] SecondSignature)> sigs = fileSignature[ext];
            foreach (var sig in sigs)
            {
                byte[] b = sig.Signature;
                int offset = sig.Offset;
                var curFileSig = new byte[b.Length];
                fs.Position = offset;
                fs.Read(curFileSig, 0, b.Length);
                flag = curFileSig.SequenceEqual(b);
                int skip = sig.Skip;
                if (skip > 0 && flag)
                {
                    byte[] secondSignature = sig.SecondSignature;
                    var secondFileSig = new byte[secondSignature.Length];
                    fs.Position = skip;
                    fs.Read(secondFileSig, 0, secondSignature.Length);
                    flag = secondFileSig.SequenceEqual(secondSignature);
                }
                if (flag) break;
            }

            return flag;
        }
    }
}
