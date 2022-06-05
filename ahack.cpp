
#include <stdio.h>
#include <string.h>

#define SEED_LENGTH 0x00000020
unsigned char seed[SEED_LENGTH] = 
{
	0xE6, 0xA1, 0x2F, 0x07, 0x9D, 0x15, 0xC4, 0x37, 0x0A, 0x20, 0x20, 0x20, 0x54, 0x4F, 0x20, 0x59, 
	0x51, 0x44, 0x2D, 0x38, 0x30, 0x20, 0x30, 0x37, 0x54, 0x4F, 0x20, 0x59, 0x4F, 0x55, 0x52, 0x20
};

#define TEST_BUFFER_LENGTH 0x00000080
unsigned char test_buffer[TEST_BUFFER_LENGTH];
unsigned short test_buffer_csum;

#define MANGLE_LEN 0x0A
unsigned char mangle[MANGLE_LEN] = 
{
    0x0A, 0x02, 0x07, 0x05, 0x01, 
    0x03, 0x09, 0x08, 0x06, 0x04
};

char dict[] = "0123456789ABCDEFGHJKMNPQRSTUVWXYZzzz";
unsigned char g_password[16] = { 0, };

#define DATA_CHUNK_LEN 0x4000
unsigned char data_chunk[DATA_CHUNK_LEN] = { 0, };

int decode(unsigned char *buffer, unsigned int buffer_len, const unsigned char *pass, unsigned int pass_len) {
  unsigned int idx = 1;
  unsigned char password[0x100] = { 0, };

  for (int i = 0; i < pass_len; i++) {
    password[i+1] = (i < MANGLE_LEN) ? pass[mangle[i]-1] : pass[i];    
  }
  password[0] = pass_len;

  while (idx <= buffer_len) {
    unsigned char pass_idx = idx % pass_len;
    unsigned char seed_idx = idx % (SEED_LENGTH - 1);

    unsigned char c = buffer[idx-1];
    c ^= password[pass_idx];
    c = ~c;
    c ^= password[pass_idx];
    unsigned short tst = c; tst <<= 1;
    if (tst > 0xFF) {
      tst++;
    }
    c = tst & 0xFF;
    c = ~c;
    c ^= password[pass_idx];
    c ^= seed[seed_idx];
    buffer[idx-1] = c;
    password[pass_idx]++;
    idx++;
  }

  return 0;
}

int do_fast_letter(const unsigned char *data, int index, int val, int pos, unsigned char *pass, int pass_len) {
  char bak = pass[index];

  for (char a = 0; a < 33;  a++) {
    unsigned char chunk[0x10];
    memcpy(chunk, data, 0x10);
    pass[index] = dict[a];
    decode(chunk, 0x10, pass, pass_len);
    if (chunk[pos] == val) {
      return 1;
    }
  }

  pass[index] = bak;
  return 0;
}

int try_header(unsigned char *pass, int pass_len) 
{
  unsigned char mumu[TEST_BUFFER_LENGTH];
  memcpy(mumu, test_buffer, TEST_BUFFER_LENGTH);

  decode(mumu, TEST_BUFFER_LENGTH, pass, pass_len);
  unsigned int sum = 0;
  for (int i = 0; i < TEST_BUFFER_LENGTH; i++) {
    sum += mumu[i];
  }

  if (sum == test_buffer_csum) {
    return 1;
  }

  return 0;
}

void initial_hack(unsigned char *data, unsigned char *pass, int pass_len) {
    memset(pass, '_', pass_len);

    do_fast_letter(data, mangle[0]-1, 'I', 0, pass, pass_len);
    do_fast_letter(data, mangle[1]-1, 'M', 1, pass, pass_len);
    do_fast_letter(data, mangle[2]-1, 'A', 2, pass, pass_len);
    do_fast_letter(data, mangle[3]-1, 'G', 3, pass, pass_len);
    do_fast_letter(data, mangle[4]-1, 'E', 4, pass, pass_len);
    do_fast_letter(data, mangle[5]-1, 'S', 5, pass, pass_len);

    do_fast_letter(data, mangle[6]-1, 0, 6, pass, pass_len);
    do_fast_letter(data, mangle[7]-1, 0, 7, pass, pass_len);
    do_fast_letter(data, mangle[8]-1, 0, 8, pass, pass_len);

    do_fast_letter(data, mangle[9]-1, 0xB8, 9, pass, pass_len);

    if (pass_len > 10) {
      do_fast_letter(data, 0x0A, 0xF9, 10, pass, pass_len);
    }

    if (pass_len > 11) {
      do_fast_letter(data, 0x0B, 0x50, 11, pass, pass_len);
    }
}

int is_valid(unsigned char *buf, unsigned int buf_len) {
  if ((buf[0x0D] == 0xFF) && (buf[0x0E] == 0xFF) && (buf[0x0F] == 0xFF)) {
    return 1;
  }
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("I need a parameter!\n");
    return 0;
  }

  FILE *f;
  f = fopen(argv[1], "rb");

  fseek(f, 0xB5, SEEK_SET);
  fread(&test_buffer_csum, 1, sizeof(unsigned short), f);

  fseek(f, 0xFC, SEEK_SET);
  fread(test_buffer, 1, TEST_BUFFER_LENGTH, f);
  fread(data_chunk, 1, DATA_CHUNK_LEN, f);
  fclose(f);


  for (int len = 10; len <= 14; len++) {
    initial_hack(data_chunk, g_password, len);
    printf("Possible password: %s (len: %d).\n", g_password, len);
    if (try_header(g_password, len)) {
      printf("Valid header checksum for password '%s'.\n",  g_password);
#ifdef _DECODE_
      decode(data_chunk, DATA_CHUNK_LEN, g_password, len);
      FILE *g;
      g = fopen("decoded.out", "wb");
      fwrite(data_chunk, 1, DATA_CHUNK_LEN, g);
      fclose(g);
#endif
    }
  }

  return 0;
}
