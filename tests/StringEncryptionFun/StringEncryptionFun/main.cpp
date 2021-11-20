#include <cstdio>

static char g_encrypted[256] = "\x1C\x00\x12\x0e\x0f\x15\x46\x0f\x15\x46\x07\x08\x46\x03\x08\x05\x14\x1f\x16\x12\x03\x02\x46\x15\x12\x14\x0f\x08\x01\x66";

void decrypt(char* decrypted, const char* encrypted);

int main()
{
	char decrypted[256];
	decrypt(decrypted, g_encrypted);
	puts(decrypted);
}