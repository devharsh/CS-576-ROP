char exitshell[] = "\x31\xdb\xb0\x01\xcd\x80";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)exitshell;
}
