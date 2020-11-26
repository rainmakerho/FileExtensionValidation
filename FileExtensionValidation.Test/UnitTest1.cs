using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FileExtensionValidation;

namespace FileExtensionValidation.Test
{
    [TestClass]
    public class UnitTest1
    {
        private static string _folderPath;
        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            _folderPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            _folderPath = Path.Combine(_folderPath, "Files");
        }

        [TestMethod]
        public void Should_True_Validate_JPG()
        {
            var fileName = "1.jpg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }

        [TestMethod]
        public void Should_True_Validate_FS_JPG()
        {
            var fileName = "1.jpg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fs = File.OpenRead(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fs, null);

            Assert.IsTrue(isValidFileExtension);

        }


        [TestMethod]
        public void Should_True_Validate_7Z()
        {
            var fileName = "2.7z";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }


        [TestMethod]
        public void Should_True_Validate_BMP()
        {
            var fileName = "3.bmp";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }

        [TestMethod]
        public void Should_True_Validate_TIFF()
        {
            var fileName = "4.tif";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }

        [TestMethod]
        public void Should_True_Validate_RTF()
        {
            var fileName = "5.rtf";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }

        [TestMethod]
        public void Should_True_Validate_PPT()
        {
            var fileName = "6.ppt";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }

        [TestMethod]
        public void Should_True_Validate_PPTX()
        {
            var fileName = "7.pptx";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);

        }
        
        [TestMethod]
        public void Should_True_Validate_DOC() 
        {
            var fileName = "8.doc";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_DOCX()
        {
            var fileName = "9.docx";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_ODT()
        {
            var fileName = "10.odt";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_ODS()
        {
            var fileName = "11.ods";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_XLSX()
        {
            var fileName = "12.xlsx";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_XLS()
        {
            var fileName = "13.xls";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_DAT()
        {
            var fileName = "14.dat";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_AVI()
        {
            var fileName = "15.avi";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MOV()
        {
            var fileName = "16.mov";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_FS_MOV()
        {
            var fileName = "16.mov";
            var filePath = Path.Combine(_folderPath, fileName);
            var fs = File.OpenRead(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fs, null);

            Assert.IsTrue(isValidFileExtension);
        }


        [TestMethod]
        public void Should_True_Validate_WMV()
        {
            var fileName = "17.wmv";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_JPEG()
        {
            var fileName = "18.jpeg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_TXT()
        {
            var fileName = "19.txt";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_GIF()
        {
            var fileName = "20.gif";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_RM()
        {
            var fileName = "21.rm";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_PNG()
        {
            var fileName = "22.png";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_PDF()
        {
            var fileName = "23.pdf";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_ODP()
        {
            var fileName = "24.odp";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_WAV()
        {
            var fileName = "25.wav";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_ODG()
        {
            var fileName = "26.odg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_3GP()
        {
            var fileName = "27.3gp";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_M4V()
        {
            var fileName = "28.m4v";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MKV()
        {
            var fileName = "29.mkv";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MP4()
        {
            var fileName = "30.mp4";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MPG()
        {
            var fileName = "31.mpg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_RAR()
        {
            var fileName = "32.rar";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MP3()
        {
            var fileName = "33.mp3";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_TIF()
        {
            var fileName = "34.tif";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_MPEG()
        {
            var fileName = "35.mpeg";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

        [TestMethod]
        public void Should_True_Validate_ZIP()
        {
            var fileName = "36.zip";
            var filePath = Path.Combine(_folderPath, fileName);
            var fileData = File.ReadAllBytes(filePath);

            var isValidFileExtension = FileExtensionValidator.IsValidFileExtension(fileName, fileData, null);

            Assert.IsTrue(isValidFileExtension);
        }

    }
}
