__author__ = 'khanta'
import os
import sys
import argparse
import datetime
import signal
import struct
from collections import namedtuple
from sys import platform as _platform


debug = 0
#References Microsoft's FAT General Overview 1.03
# <editor-fold desc="Boot Sector Variables">

BytesPerSector = ''  #Offset 11 - 2 bytes
SectorsPerCluster = ''  #Offset 13 - 1 byte
ReservedSectorCount = ''  #Offset 14 - 2 bytes
NumberOfFATs = ''  #Offset 16 - 1 byte
TotalSectors = ''  #Offset 32 - 4 bytes
# Start of FAT32 Structure
FAT32Size = ''  #Offset 36 - 4 bytes
RootCluster = ''  #Offset 44 - 4 bytes
FSInfoSector = ''  #Offset 48 - 2 bytes
ClusterSize = ''
TotalFAT32Sectors = ''
TotalFAT32Bytes = ''
DataAreaStart = ''
DataAreaEnd = ''
RootDirSectors = 0  #Always 0 for Fat32 Per MS Documentation
#FSINFO
Signature = ''
NumberOfFreeClusters = 0
NextFreeCluster = 0
BootSectorSize = 512
# </editor-fold>

# <editor-fold desc="Global Variables">
FirstChar = ''
EightDotThree = ''
FileAttributes = ''
CreatedTimeTenths = ''
CreateTimeHMS = ''
CreateDay = ''
AccessDay = ''
WrittenTimeHMS = ''
WrittenDay = ''
SizeOfFile = ''
FileSize = 0
HighTwoBytesFirst = ''
LowTwoBytesFirst = ''
FreeDirOffset = ''
#EndOfChain = 0xfffffff8
EndOfChain = 0x0fffffff
EndOfFile = 0x0fffffff
EmptyCluster = 0x00000000
DamagedCluster = 0x0ffffff7
ValidBytesPerSector = [512, 1024, 2048, 4096]

TotalChunks = 0  #The total clusters that need to be written. This will be int * remainder
FirstCluster = 0  #The first cluster.  This is written to the RootDir
ChunkList = []
ReadClusterList = []
MD5HashValue = ''
FileName = ''
FileData = ''
SkippedClusters = ''

# </editor-fold>
class NotValidBootSector(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


eventlog = namedtuple("_EVENTLOGRECORD", "field1 field2 field3")

def GetDriveFormat(os, volume):
    if os == 'posix':
        drive = volume
    elif os == 'Windows':
        drive = '\\.\%s:' % volume
    return drive


def FileNamePad(file):
    status = True
    error = ''
    global FileName

    try:
        if (debug >= 1):
            print('Entering FileNamePad:')
        if (debug >= 2):
            print('\tFilename Passed in: ' + str(file))
        padding = 0
        extpad = 0
        extension = ''
        length = len(file)
        if (length == 12):
            if "." in str(file):
                filename = file.replace('.', '')
                filename = filename.encode('ascii').upper()
                if (debug >= 2):
                    print('\tFilename is 8.3 --> ' + str(filename))
                FileName = filename
            else:
                error = 'Long Filenames not Supported.'
        else:
            if (length > 12):
                error = 'Long Filenames not Supported.'
            else:
                if "." in str(file):
                    if (debug >= 2):
                        print('\tFilename has Period in it. -->' + str(file))
                    parts = file.split('.')
                    extension = parts[1]
                    if (len(extension) < 3):
                        extpad = 3 - len(extension)
                    extension = extension.encode('ascii').upper()
                    extension += extpad * b'\x20'
                    filename = parts[0]
                    if (debug >= 2):
                        print('\tExtension: ' + str(extension))
                        print('\tFilc: ' + str(filename))
                    if (len(filename) < 8):
                        padding = 8 - len(filename)
                        if (debug >= 2):
                            print('\tFilename and Length - ' + str(filename) + ' : ' + str(padding))
                        filename = filename.encode('ascii').upper()
                        filename += padding * b'\x20'
                    else:
                        filename = file.encode('ascii').upper()
                else:
                    if (debug >= 2):
                        print('\tFilename does not have period in it. -->' + str(file))
                    if (len(file) < 11):
                        padding = 11 - len(file)
                    filename = file.encode('ascii').upper()
                    filename += padding * b'\x20'
                    FileName = filename
        if not (extension == ""):
            #extension = extension.encode('ascii').upper()
            filename = filename + extension
            FileName = filename
            if (debug >= 2):
                print('\tFilename Length/Padding Length: ' + str(len(file)) + '/' + str(padding))
                print('\tFilenamc: ' + str(filename))
        else:
            if (debug >= 2):
                print('\tFilename Length/Padding Length: ' + str(len(file)) + '/' + str(padding))
                print('\tFilenamc: ' + str(filename))
        FileName = filename
    except:
        status = False
    finally:
        return status, error


def ReadBootSector(volume):
    # <editor-fold desc="Global Variables">
    global DataAreaStart
    global BytesPerSector
    global SectorsPerCluster
    global ReservedSectorCount
    global NumberOfFATs
    global TotalSectors
    # Start of FAT32 Structure
    global FAT32Size
    global RootCluster
    global FSInfoSector
    global ClusterSize
    global BootSector
    global TotalFAT32Sectors
    global TotalFAT32Bytes
    global DataAreaStart
    global DataAreaEnd
    global FirstDataSector
    # </editor-fold>
    status = True
    error = ''

    # Reads the specified bytes from the drive
    try:
        if (debug >= 1):
            print('Entering ReadBootSector:')
        #if (True):
        #    f = os.fdopen(os.open('\\\\.\\c:', os.O_RDONLY|os.O_BINARY), "rb")
            if (debug >= 1):
                print('\tReading Drive.')
        with open('\\\\.\\c:', "rb") as f:
            bytes = f.read(BootSectorSize)
            BytesPerSector = struct.unpack("<H", bytes[11:13])[0]
            if (BytesPerSector not in ValidBytesPerSector):
                raise NotValidBootSector('Not a Valid Boot Sector')
            SectorsPerCluster = struct.unpack("<b", bytes[13:14])[0]
            ReservedSectorCount = struct.unpack("<H", bytes[14:16])[0]
            NumberOfFATs = struct.unpack("<b", bytes[16:17])[0]
            TotalSectors = struct.unpack("i", bytes[32:36])[0]
            FAT32Size = struct.unpack("i", bytes[36:40])[0]
            RootCluster = struct.unpack("i", bytes[44:48])[0]
            FSInfoSector = struct.unpack("<H", bytes[48:50])[0]

            #Calculate some values
            ClusterSize = SectorsPerCluster * BytesPerSector
            TotalFAT32Sectors = FAT32Size * NumberOfFATs
            TotalFAT32Bytes = FAT32Size * BytesPerSector

            DataAreaStart = ReservedSectorCount + TotalFAT32Sectors
            DataAreaEnd = TotalSectors - 1  #Base 0
            #Double Check per MS Documentation
            #FirstDataSector = BPB_ReservedSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors;
            FirstDataSector = ReservedSectorCount + (NumberOfFATs * FAT32Size) + RootDirSectors
            if (debug >= 1):
                print('\tBytes per Sector: ' + str(BytesPerSector))
                print('\tSectors per Cluster: ' + str(SectorsPerCluster))
                print('\tCluster Sizc: ' + str(ClusterSize))
                print('\tRoot Cluster: ' + str(RootCluster))
                print('\tFSInfo Cluster: ' + str(FSInfoSector))
                print('\tTotal Sectors: ' + str(TotalSectors))
                print('\tReserved Sector Count: ' + str(ReservedSectorCount))
                print('\tReserved Sectors: ' + '0  - ' + str(ReservedSectorCount - 1))
                print('\tFAT Offset: ' + str(ReservedSectorCount))
                print('\tFAT Offset (Bytes): ' + str(ReservedSectorCount * BytesPerSector))
                print('\tNumber of FATs: ' + str(NumberOfFATs))
                print('\tFAT32 Sizc: ' + str(FAT32Size))
                print('\tTotal FAT32 Sectors: ' + str(TotalFAT32Sectors))
                print('\tFAT Sectors: ' + str(ReservedSectorCount) + ' - ' + str(
                    (ReservedSectorCount - 1) + (FAT32Size * NumberOfFATs)))
                print('\tData Area: ' + str(DataAreaStart) + ' - ' + str(DataAreaEnd))
                print('\tData Area Offset (Bytes): ' + str(DataAreaStart * BytesPerSector))
                #print('\tRoot Directory: ' + str(DataAreaStart) + ' - ' + str(DataAreaStart + 3))
                #Extra Testing
                print('\t   First Data Sector: ' + str(FirstDataSector))
    except IOError:
        status = False
        error = 'Volume ' + str(volume) + ' does not exist.'
    except NotValidBootSector:
        status = False
        error = 'Volume ' + str(volume) + ' contains an invalid boot sector.'
    except:
        status = False
        error = 'Cannot read Boot Sector.'
    finally:
        return status, error


def FileNamePad(file):
    status = True
    error = ''
    global FileName

    try:
        if (debug >= 1):
            print('Entering FileNamePad:')
        if (debug >= 2):
            print('\tFilename Passed in: ' + str(file))
        padding = 0
        extpad = 0
        extension = ''
        length = len(file)
        if (length == 12):
            if "." in str(file):
                filename = file.replace('.', '')
                filename = filename.encode('ascii').upper()
                if (debug >= 2):
                    print('\tFilename is 8.3 --> ' + str(filename))
                FileName = filename
            else:
                error = 'Long Filenames not Supported.'
        else:
            if (length > 12):
                error = 'Long Filenames not Supported.'
            else:
                if "." in str(file):
                    if (debug >= 2):
                        print('\tFilename has Period in it. -->' + str(file))
                    parts = file.split('.')
                    extension = parts[1]
                    if (len(extension) < 3):
                        extpad = 3 - len(extension)
                    extension = extension.encode('ascii').upper()
                    extension += extpad * b'\x20'
                    filename = parts[0]
                    if (debug >= 2):
                        print('\tExtension: ' + str(extension))
                        print('\tFilc: ' + str(filename))
                    if (len(filename) < 8):
                        padding = 8 - len(filename)
                        if (debug >= 2):
                            print('\tFilename and Length - ' + str(filename) + ' : ' + str(padding))
                        filename = filename.encode('ascii').upper()
                        filename += padding * b'\x20'
                    else:
                        filename = file.encode('ascii').upper()
                else:
                    if (debug >= 2):
                        print('\tFilename does not have period in it. -->' + str(file))
                    if (len(file) < 11):
                        padding = 11 - len(file)
                    filename = file.encode('ascii').upper()
                    filename += padding * b'\x20'
                    FileName = filename
        if not (extension == ""):
            #extension = extension.encode('ascii').upper()
            filename = filename + extension
            FileName = filename
            if (debug >= 2):
                print('\tFilename Length/Padding Length: ' + str(len(file)) + '/' + str(padding))
                print('\tFilenamc: ' + str(filename))
        else:
            if (debug >= 2):
                print('\tFilename Length/Padding Length: ' + str(len(file)) + '/' + str(padding))
                print('\tFilenamc: ' + str(filename))
        FileName = filename
    except:
        status = False
    finally:
        return status, error

def ReadData(volume, clusterlist, size): 
    status = True
    error = '' 
    global FileData 
    try: 
        if (debug >= 1): 
            print('Entering ReadData:') 
        if (debug >= 3): 
            print('Volume Passed in: ' + str(volume)) 
            print('Clusterlist Passed in: ' + str(clusterlist)) 
            print('Size in: ' + str(size)) 
        readchunk = bytearray() 
        with open('\\\\.\\c:', "rb") as f: 
            for cluster in clusterlist:  #New Offset is 2 (Cluster) 
                seeker = (cluster * ClusterSize + (DataAreaStart * BytesPerSector) - 2 * ClusterSize) 
                f.seek(seeker)  #Each ClusterNum - 2 (Offset) * Bytes per cluster + (DataAreaStart * BytesPerSector) 
                if (debug >= 1): 
                    print('\tSeeking to Cluster (Bytes) [Cluster]: ' + '[' + str(cluster) + ']' + str(seeker)) 
                readchunk += f.read(ClusterSize) 
            FileData = readchunk[0:size] 
            if (debug >= 3): 
                print('\tFile Data: ' + str(FileData)) 
    except: 
        error = ('Error: Cannot Read Data.') 
        status = False
    finally: 
        return status, error 


def SearchDirectory(volume, file):
    status = True
    error = ''

    try:
        if (debug >= 1):
            print('Entering SearchDirectory:')
        if (debug >= 2):
            print('\tVolume passed in: ' + str(volume))
            print('\tFile passed in: ' + str(file))
        s1 = FileName
        if (debug >= 2):
            print('\tFilename to Search: ' + str(s1))
        match = False
        global FirstCluster
        global FileSize
        with open('\\\\.\\c:', "rb") as f:
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
                print('\tOpening volume: ' + str(volume))
            x = 0
            while (True):
                f.seek(BytesPerSector * FirstDataSector + x)
                bytes = f.read(32)  #Size of FAT32 Directory
                FirstChar = struct.unpack("b", bytes[0:1])[0]
                
                if not (FirstChar == 0x00):  #Check for Unallocated Dir (This means exit!)
                    if not (FirstChar == 0xe5):  #Check for Unallocated Dir
                        filename = bytes[0:11]
                        if (debug >= 3):
                            print('\tFirst Character not 0xe5 or 0x00.')
                            print('\tReading First 11 Bytes.')
                            print('\tDirectory Value: ' + str(filename))
                            #print('t' + )
                            #print('\tDir Filename - Filename: ' + str(filename.upper()) + ' - ' + str(s1))
                        if (filename.upper() == s1):
                            match = True
                            if (debug >= 2):
                                print('\tFound Value That Matched: ' + str(s1))
                            #if not (write):
                            ba = bytearray(bytes[26:28])
                            ba += bytes[20:22]
                            if (debug >= 2):
                                print('\tHigh/Low Bytes Bytearray [Length]: ' + '[' + str(len(ba)) + ']' + str(ba))
                            FirstCluster = struct.unpack("<i", ba)[0]
                            if (debug >= 1):
                                print('\tFirst Cluster: ' + str(FirstCluster))
                            ba1 = bytearray(bytes[28:32])
                            FileSize = struct.unpack("<i", ba1)[0]
                            if (debug >= 2):
                                print('\tFilesize Located in Directory [Bytes]: ' + str(FileSize))
                            else:
                                return match
                            break
                        else:
                            x += 32
                    else:
                        x += 32
                else:
                    x += 32
    except:
        error = 'Error Searching Directory.'
        status = False
    finally:
        return match

def SearchFAT(volume, FATOffset, FirstCluster):
    status = True
    error = ''
    global ReadClusterList

    try:
        if (debug >= 1):
            print('Entering SearchFAT:')
            print('\tFirstCluster passed in: ' + str(FirstCluster))
            print('\tVolume passed in: ' + str(volume))

        nextcluster = FirstCluster
        ReadClusterList.append(nextcluster)
        y = 0
        with open('\\\\.\\c:', "rb") as f:
            f.seek(FATOffset * BytesPerSector)
            bytes = f.read(TotalFAT32Bytes)
            if (debug >= 2):
                print('\tSeeking to FAT Offset (Bytes): ' + str(FATOffset * BytesPerSector))
            while (y <= TotalFAT32Bytes):
                y += 4
                chunk = bytes[nextcluster * 4:nextcluster * 4 + 4]
                nextcluster = struct.unpack("<i", chunk)[0]
                if (debug >= 3):
                    print('\tCluster Read [Length]: ' + '[' + str(len(chunk)) + ']' + str(chunk))
                if (debug >= 2):
                    print('\tNext Cluster: ' + str(nextcluster))
                if (nextcluster != 268435455):
                    ReadClusterList.append(nextcluster)
                else:
                    break
        if (debug >= 2):
            print('\tCluster List: ' + str(ReadClusterList))
            #return ReadClusterList
    except:
        error = 'Error: Cannot Search FAT.'
        status = False
    finally:
        return status, error

def WriteData(volume, file, clusterlist):
    status = True
    error = ''
    global ReadClusterList
    global FileData

    #try:
    if (debug >= 1):
        print('Entering WriteData:')
        chunk = ''
        #Write data off of Data Section - Each Cluster is 2048 bytes and it starts at Cluster 2
        #Each cluster is 2048 bytes
        #clusterlist.insert(0, FirstCluster) #Adding First Cluster back in
        FileData = FileData.replace(b'\x10\x02\x00\x00\x08', b'\x11\x02\x00\x00\x10')
        sys.exit()
        with open('\\\\.\\c:', "rb+") as f:
            if (debug >= 1):
                print('Opening Volume: ' + str(volume))
            #print (clusterlist)
            for cluster in clusterlist:  #New Offset is 2 (Cluster)
                seeker = (cluster * ClusterSize + (DataAreaStart * BytesPerSector) - 2 * ClusterSize)
                f.seek(seeker)  #Each ClusterNum - 2 (Offset) * Bytes per cluster + (DataAreaStart * 512)
                if (debug >= 1):
                    print('\tSeeking to Cluster (Bytes) [Cluster]: ' + '[' + str(cluster) + ']' + str(seeker))
                chunk = 512 * b'\x00'
                if (debug >= 1):
                    print('\tData Chunk Written: ' + str(chunk))
                f.write(chunk)
        if (debug >= 1):
            print('\tCompleted Writing Data.')
    #except:
        #error = 'Error: Cannot Write Data.'
        #status = False
    #finally:
        return status, error

def signal_handler(signal, frame):
    print('Ctrl+C pressed. Exiting.')
    sys.exit(0)


def Header():
    print('')
    print('+------------------------------------------------------------------------+')
    print('|Event Log Modification Utility (EVT)                                    |')
    print('+-------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                     |')
    print('+------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+------------------------------------------------------------------------+')


def Failed(error):
    print('  * Error: ' + str(error))
    print('+------------------------------------------------------------------------+')
    print('| Failed.                                                                |')
    print('+------------------------------------------------------------------------+')
    sys.exit(1)


def Completed():
    print('| Completed.                                                             |')
    print('+------------------------------------------------------------------------+')
    print('+------------------------------------------------------------------------+')
    sys.exit(0)



signal.signal(signal.SIGINT, signal_handler)


def main(argv):

    try:
        global debug
        file = 'SECEVENTEVT'
        #parse the command-line arguments
        status = True
        error = ''
        parser = argparse.ArgumentParser(description="A FAT32 file system writer that forces fragmentation.",
                                         add_help=True)
        parser.add_argument('-v', '--volume', help='The volume to write the fragmented file to.', required=True)
        parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
        parser.add_argument('--version', action='version', version='%(prog)s 1.5')
        args = parser.parse_args()
        if _platform == "linux" or _platform == "linux2":
            os = 'Linux'
        elif _platform == "darwin":
            os = 'Mac'
        elif _platform == "win32":
            os = 'Windows'
        if (args.volume):
            volume = args.volume
            #if (os == 'Windows'):
            #    GetDriveFormat(os, volume)
        if (args.debug):
            debug = args.debug
            debug = int(debug)

        if (debug >= 1):
            print('Entered main:')
            print('\tVolumc: ' + str(volume))
            print('\tOperating System: ' + str(os))
            print('\tDebug Level: ' + str(debug))
            #if (os == 'Windows'):
            #    print ('Error: System not supported.')
            #    sys.exit(1)



        #=======================================================================================================================
        Header()
        status, error = ReadBootSector(volume)
        if (status):
            print('| [+] Reading Boot Sector.                                               |')
        else:
            print('| [-] Reading Boot Sector.                                               |')
            Failed(error)
        status, error = FileNamePad(file)
        if (status):
            print('| [+] Verifying Filename.                                                |')
        else:
            print('| [-] Verifying Filename.                                                |')
            Failed(error)
        match = SearchDirectory(volume, file)
        if (match):
            print('| [+] Searching Directory.                                               |')
        else:
            print('| [-] Searching Directory.                                               |')
            Failed('File does not exist in the directory')
        status, error = SearchFAT(volume, ReservedSectorCount, FirstCluster)
        if (status):
            print('| [+] Searching FAT.                                                     |')
        else:
            print('| [-] Searching FAT.                                                     |')
            Failed(error)
        status, error = ReadData(volume, ReadClusterList, FileSize)
        if (status):
            print('| [+] Reading Data.                                                      |')
        else:
            print('| [-] Reading Data.                                                      |')
            Failed(error)
        status, error = WriteData(volume, file, ReadClusterList)
        if (status):
            print('| [+] Zapping Event Log.                                                 |')
        else:
            print('| [-] Zapping Event Log.                                                 |')
            Failed(error)
        Completed()



    except IOError:
        sys.exit('Error: File ' + str(file) + ' does not exist.')


main(sys.argv[1:])