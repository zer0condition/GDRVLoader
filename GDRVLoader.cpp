#include "global.h"
#include "binary/dropper.h"

const wchar_t* DriverPath = L"C:\\Windows\\System32\\Drivers\\gdrv.sys";

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        printf("Invalid arguments. Usage: GDRVLoader.exe TargetDriver.sys\n");
        return false;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    char input[10];
    printf("Load or unload driver?\n");
    scanf("%s", input);

    if (strcmp(input, "LOAD") == 0 || strcmp(input, "load") == 0)
    {
        if (DropDriverFromBytes(DriverPath))
        {
            // Load driver
            Status = WindLoadDriver((PWCHAR)DriverPath, argv[1], FALSE);

            if (NT_SUCCESS(Status))
                printf("Driver loaded successfully\n");

            DeleteFile((PWSTR)DriverPath);
        }
    }
    else if (strcmp(input, "Unload") == 0 || strcmp(input, "unload") == 0)
    {
        // Unload driver
        Status = WindUnloadDriver((PWCHAR)argv[1], 0);
        if (NT_SUCCESS(Status))
            printf("Driver unloaded successfully\n");
    }

    if (!NT_SUCCESS(Status))
        printf("Error: %08X\n", Status);

    return true;
}
