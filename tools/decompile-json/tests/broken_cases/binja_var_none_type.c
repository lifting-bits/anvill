/*
* This test causes BinaryNinja to produce Variables with None type
* This should be handled in extract_types
*/
void xor_swap(unsigned char buf[]) {
  buf[0] = buf[0] ^ buf[1];
  buf[1] = buf[0] ^ buf[1];
  buf[0] = buf[0] ^ buf[1];  
}
//Simple atoi
unsigned char atoi(const char * s) {
 return s[0] - '0';
}
int main(int argc, const char *argv[]) {	
  unsigned char buf[3] = {9, 10, 11};
  int buff_size = sizeof(buf)/sizeof(buf[0]);
  for(int i = 1; i < argc && i < buff_size; i++) {
    buf[i - 1] = (unsigned char)atoi(argv[i]);
  }
  xor_swap(buf);
  return 0;
}
