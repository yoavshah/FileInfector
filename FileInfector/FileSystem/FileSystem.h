#pragma once
#include <Windows.h>
#include "../custom_std.h"

#define NUMBER_OF_DRIVES 26


namespace FileSystem
{
    namespace Drives
    {
        enum class DriveType {
            NotExist,
            Unknown,
            Invalid,
            Removable,
            HardDrive,
            Network,
            CDROM,
            RAMDisk
        };

        typedef void (*HardDiskIterator)(const wchar_t* drivePath, DriveType driveType);

        typedef struct _HardDiskDrive
        {
            DriveType driveType;
            unsigned short driveIndex;

        } HardDiskDrive;

        struct Drives
        {
            unsigned short numberOfDrives;
            HardDiskDrive drives[NUMBER_OF_DRIVES];
        };

        BOOL GetAllConnectedDrives(Drives* drives);

        void DriveIndexToPathW(unsigned short driveIndex, wchar_t* drivePath);

        BOOL IterateDrives(HardDiskIterator hardDiskIteratorFunction);


    }
    

    namespace Files
    {
        typedef void (*FileIterator)(const wchar_t* filePath);
        typedef bool (*FolderIterator)(const wchar_t* folderPath);


        BOOL IteratePath(const wchar_t* path, FileIterator fileIteratorFunction, FolderIterator folderIteratorFunction);
    }
    

}
