int base64encode_len(int len);
int base64encode(char *encoded, const char *string, int len);
int base64decode_len(const char *bufcoded);
int base64decode_binary(unsigned char *bufplain, const char *bufcoded);
int base64decode(char *bufplain, const char *bufcoded);
