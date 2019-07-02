#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes.h"
#include "keys.h"

#define STATE_SIZE 4
#define NUM_ROUNDS 4

#define SWAP(x) ((x >> 24) & 0xff | (x >> 8) & 0xff00 | (x << 8) & 0xff0000 | (x << 24) & 0xff000000)

struct mm_file_type
{
	char* name;
	char* fileName;
	size_t fileSize;
	size_t offset;
	uint32_t* key_table;
};

void rand_init(uint32_t *rand_state, uint32_t in1, uint32_t in2, uint32_t in3, uint32_t in4)
{
	int cond = in1 | in2 | in3 | in4;
	
	rand_state[0] = cond ? in1 : 1;
	rand_state[1] = cond ? in2 : 0x6C078967;	
	rand_state[2] = cond ? in3 : 0x714ACB41;
	rand_state[3] = cond ? in4 : 0x48077044;
}

uint32_t rand_gen(uint32_t *rand_state)
{	
	uint32_t n = rand_state[0] ^ rand_state[0] << 11;
	rand_state[0] = rand_state[1];
	n ^= n >> 8 ^ rand_state[3] ^ rand_state[3] >> 19;
	rand_state[1] = rand_state[2];
	rand_state[2] = rand_state[3];
	rand_state[3] = n;
	return n;
}

void gen_key(uint32_t *key_table, uint32_t *out_key, uint32_t *rand_state)
{
	out_key[0] = 0;
	
	for (int i = 0; i < STATE_SIZE; i++)
	{		
		for (int j = 0; j < NUM_ROUNDS; j++)
		{
			out_key[i] <<= 8;
			out_key[i] |= (key_table[rand_gen(rand_state) >> 26] >> ((rand_gen(rand_state) >> 27) & 24)) & 0xFF;
		}
	}
}

int usage(int argc, char **argv)
{
	printf("Usage: %s input output\n", argv[0]);
	return -1;
}

char endsWith(const char* a, const char* b)
{
	if (!a || !b)
	{
		return 0;
	}

	int lenA = strlen(a);
	int lenB = strlen(b);

	if (lenB > lenA)
	{
		return 0;
	}

	return strcmp(a + lenA - lenB, b) == 0;
}

struct mm_file_type file_types[] = {
	{ "save", "save.dat", 0xC000, 0x0, save_key_table },
	{ "quest", "quest.dat", 0xC000, 0x0, quest_key_table },
	{ "later", "later.dat", 0xC000, 0x0, later_key_table },
	{ "replay", ".dat", 0x68000, 0x0, replay_key_table },
	{ "network", "network.dat", 0x48000, 0x0, network_key_table },
	{ "thumb", ".btl", 0x1C000, 0x0, thumb_key_table },
	{ "course", ".bcd", 0x5C000, 0x10, course_key_table }
};

struct mm_file_type* getFileType(const char* fileName, size_t size)
{
	for (int i = 0; i < sizeof(file_types) / sizeof(struct mm_file_type); i++)
	{
		if (file_types[i].fileSize == size && endsWith(fileName, file_types[i].fileName))
		{
			return &file_types[i];
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	char encrypt = 0;
	char* inFileName = NULL;
	char* outFileName = NULL;

	for (int i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'e':
				encrypt = 1;
				break;
			default:
				return usage(argc, argv);
			}
		}
		else if(!inFileName)
		{
			inFileName = argv[i];
		}
		else if (!outFileName)
		{
			outFileName = argv[i];
		}
		else
		{
			return usage(argc, argv);
		}
	}

	if (!inFileName || !outFileName)
	{
		return usage(argc, argv);
	}
	
	FILE *in = fopen(inFileName, "rb");
	FILE *out = fopen(outFileName, "wb");
	
	fseek(in, 0, SEEK_END);
	size_t sz = ftell(in);
	rewind(in);
	
	struct AES_ctx ctx;
	
	uint32_t rand_state[STATE_SIZE];
	uint32_t key_state[STATE_SIZE];


	struct mm_file_type* file_type = getFileType(inFileName, sz);

	if (!file_type)
	{
		printf("unsupported file: %s\n", inFileName);
		return -1;
	}

	char *buf = malloc(file_type->fileSize);
	memset(buf, 0, file_type->fileSize);

	fread(buf, 1, file_type->fileSize, in);
	fclose(in);

	char *end = buf + sz - 0x30;

	rand_init(rand_state, *(uint32_t *)&end[0x10], *(uint32_t *)&end[0x14], *(uint32_t *)&end[0x18], *(uint32_t *)&end[0x1C]);
	gen_key(file_type->key_table, key_state, rand_state);

	AES_init_ctx_iv(&ctx, (uint8_t *)key_state, end);

	if (encrypt)
	{
		printf("Encrypting %s %s to %s...\n", file_type->name, inFileName, outFileName);
		AES_CBC_encrypt_buffer(&ctx, buf + file_type->offset, sz - (0x30 + file_type->offset));
	}
	else
	{
		printf("Decrypting %s %s to %s...\n", file_type->name, inFileName, outFileName);
		AES_CBC_decrypt_buffer(&ctx, buf + file_type->offset, sz - (0x30 + file_type->offset));
	}

	fwrite(buf + file_type->offset, 1, sz - (0x30 + file_type->offset), out);
	fclose(out);

	free(buf);
	
	puts("Done!");
	
	return 0;
}