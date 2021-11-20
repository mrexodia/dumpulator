__declspec(noinline) void decrypt(char* decrypted, const char* encrypted)
{
	auto size = *(unsigned short*)encrypted;
	encrypted += 2;
	for (unsigned short i = 0; i < size; i++)
		*decrypted++ = *encrypted++ ^ 0x66;
}