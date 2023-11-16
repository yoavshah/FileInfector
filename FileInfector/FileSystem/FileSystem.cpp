#include "FileSystem.h"


namespace FileSystem
{

    namespace Drives
    {

        BOOL GetAllConnectedDrives(Drives* drives)
        {
            DWORD driveMask = GetLogicalDrives();
            if (driveMask == 0) {
                return FALSE;
            }

            drives->numberOfDrives = NUMBER_OF_DRIVES;
            for (int i = 0; i < 26; ++i) {
                drives->drives[i].driveIndex = i;

                if (driveMask & (1 << i)) {
                    wchar_t driveLetterPath[5];
                    DriveIndexToPathW(i, driveLetterPath);

                    UINT driveType = GetDriveTypeW(driveLetterPath);
                    switch (driveType) {
                    case DRIVE_UNKNOWN:
                        drives->drives[i].driveType = DriveType::Unknown;
                        break;

                    case DRIVE_NO_ROOT_DIR:
                        drives->drives[i].driveType = DriveType::Invalid;
                        break;

                    case DRIVE_REMOVABLE:
                        drives->drives[i].driveType = DriveType::Removable;
                        break;

                    case DRIVE_FIXED:
                        drives->drives[i].driveType = DriveType::HardDrive;
                        break;

                    case DRIVE_REMOTE:
                        drives->drives[i].driveType = DriveType::Network;
                        break;

                    case DRIVE_CDROM:
                        drives->drives[i].driveType = DriveType::CDROM;
                        break;

                    case DRIVE_RAMDISK:
                        drives->drives[i].driveType = DriveType::RAMDisk;
                        break;
                    }
                }
                else
                {
                    drives->drives[i].driveType = DriveType::NotExist;
                }

            }
        }


        void DriveIndexToPathW(unsigned short driveIndex, wchar_t* drivePath)
        {
            wchar_t driveLetter = L'A' + driveIndex;
            drivePath[0] = driveLetter;
            drivePath[1] = L':';
            drivePath[2] = L'\\';
            drivePath[3] = L'\\';
            drivePath[4] = L'\x00';
        }

        BOOL IterateDrives(HardDiskIterator hardDiskIteratorFunction)
        {
            Drives drives;
            BOOL result = GetAllConnectedDrives(&drives);

            if (!result)
            {
                return false;
            }

            for (size_t i = 0; i < drives.numberOfDrives; i++)
            {
                HardDiskDrive harddisk = drives.drives[i];
                if (harddisk.driveType != DriveType::NotExist)
                {
                    wchar_t drivePath[5];
                    DriveIndexToPathW(i, drivePath);

                    hardDiskIteratorFunction(drivePath, harddisk.driveType);
                }
            }

            return true;


        }


    }

    namespace Files
    {

        bool AddWildcardToPath(const wchar_t* path, wchar_t* wildcardedPath, unsigned int maxPathSize)
        {
            custom_std::memset(wildcardedPath, 0x00, maxPathSize * sizeof(wchar_t));
            size_t pathSize = custom_std::wcslen(path);
            
            // Check if it cannot fit it, should not happen
            if (pathSize + 3 >= maxPathSize)
                return false;
            
            custom_std::memcpy(wildcardedPath, path, pathSize * sizeof(wchar_t));

            wildcardedPath[pathSize] = L'\\';
            wildcardedPath[pathSize + 1] = L'*';

            return true;
        }
        
        bool CombinePath(const wchar_t* path, const wchar_t* toAdd, wchar_t* combinedPath, unsigned int maxPathSize)
        {
            custom_std::memset(combinedPath, 0x00, maxPathSize * sizeof(wchar_t));
            size_t pathSize = custom_std::wcslen(path);
            size_t toAddSize = custom_std::wcslen(toAdd);

            // Check if it cannot fit it, should not happen
            if (pathSize + toAddSize + 2 >= maxPathSize)
                return false;

            custom_std::memcpy(combinedPath, path, pathSize * sizeof(wchar_t));

            combinedPath[pathSize] = L'\\';

            custom_std::memcpy(&(combinedPath[pathSize + 1]), toAdd, toAddSize * sizeof(wchar_t));

            return true;
        
        }


        // Receives path of the folder to iterate
        BOOL IteratePath(const wchar_t* path, FileIterator fileIteratorFunction, FolderIterator folderIteratorFunction)
        {
            const unsigned int maxPathSize = MAX_PATH * 2;
            wchar_t checkPath[maxPathSize];
            wchar_t innerPath[maxPathSize];

            WIN32_FIND_DATAW findFileData;

            AddWildcardToPath(path, checkPath, maxPathSize);

            HANDLE hFind = FindFirstFileW(checkPath, &findFileData);

            if (hFind == INVALID_HANDLE_VALUE) 
                return false;

            do {
 
                if ((findFileData.cFileName[0] == L'.' && findFileData.cFileName[1] == L'.' && findFileData.cFileName[2] == L'\x00') ||
                    (findFileData.cFileName[0] == L'.' && findFileData.cFileName[1] == L'\x00'))
                {
                    continue;
                }

                CombinePath(path, findFileData.cFileName, innerPath, maxPathSize);

                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if (folderIteratorFunction(innerPath))
                    {
                        IteratePath(innerPath, fileIteratorFunction, folderIteratorFunction);
                    }
                }
                else 
                {
                    fileIteratorFunction(innerPath);
                }

            } while (FindNextFileW(hFind, &findFileData) != 0);

            FindClose(hFind);
        
            return true;
        }



    }
}

