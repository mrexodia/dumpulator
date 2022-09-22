#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void console_output_test()
{
    printf( "Console output test\n" );
}

void read_file_test()
{
    FILE* fp = NULL;
    char* buffer = NULL;

    fp = fopen( "C:\\Windows\\Temp\\test_file.txt", "r" );

    if( fp )
    {
        fseek( fp, 0, SEEK_END );
        long len = ftell( fp );
        fseek( fp, 0, SEEK_SET );
        buffer = ( char* )malloc( len );
        if( buffer )
        {
            fread( buffer, 1, len, fp );
        }
        fclose( fp );
    }

    if( buffer )
    {
        printf( "read_file_test: %s\n", buffer );
    }
}

void write_file_test()
{
    FILE* fp = NULL;
    char* buffer = NULL;

    fp = fopen( "C:\\Windows\\Temp\\test_file.txt", "w+" );

    if( fp )
    {
        rewind( fp );
        fprintf( fp, "testing write file\n" );

        fseek( fp, 0, SEEK_END );
        long len = ftell( fp );
        fseek( fp, 0, SEEK_SET );
        buffer = ( char* )malloc( len );
        if( buffer )
        {
            fread( buffer, 1, len, fp );
        }
        fclose( fp );
    }

    if( buffer )
    {
        printf( "write_file_test: %s\n", buffer );
    }
}

void write_file_offset_test()
{
    FILE* fp = NULL;
    char* buffer = NULL;

    fp = fopen( "C:\\Windows\\Temp\\test_file.txt", "w+" );

    if( fp )
    {
        fseek( fp, 5, SEEK_SET );
        fprintf( fp, "--writing file offset--\n" );

        fseek( fp, 0, SEEK_END );
        long len = ftell( fp );
        fseek( fp, 0, SEEK_SET );
        buffer = ( char* )malloc( len );
        if( buffer )
        {
            fread( buffer, 1, len, fp );
        }
        fclose( fp );
    }

    if( buffer )
    {
        printf( "write_file_test: %s\n", buffer );
    }
}

int main()
{
    console_output_test();
    read_file_test();
    write_file_test();
    write_file_offset_test();
    return 0;
}

#ifdef __cplusplus
}
#endif